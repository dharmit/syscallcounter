/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	syscallcounterv1alpha1 "github.com/dharmit/syscallcounter/api/v1alpha1"
	"github.com/dharmit/syscallcounter/bpf"
)

// SyscallCounterReconciler reconciles a SyscallCounter object
type SyscallCounterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=syscallcounter.dharmitshah.com,resources=syscallcounters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=syscallcounter.dharmitshah.com,resources=syscallcounters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=syscallcounter.dharmitshah.com,resources=syscallcounters/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SyscallCounter object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *SyscallCounterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Reconciling SyscallCounterReconciler")
	var err error

	// Allow the current process to lock memory for eBPF resources.
	// This may not be needed if running as root or with specific capabilities.
	//err := rlimit.RemoveMemlock()
	//if err != nil {
	//	logger.Error(err, "Failed to remove memlock limit")
	//	return ctrl.Result{}, err // TODO: check if requeue'ing is required
	//}

	// 1. Fetch SyscallCounter instance
	syscallCounter := &syscallcounterv1alpha1.SyscallCounter{}
	err = r.Client.Get(ctx, req.NamespacedName, syscallCounter)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("SyscallCounter resource not found. Ignoring as it might be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get SyscallCounter")
		return ctrl.Result{}, err
	}

	// 2. Handle deletion
	isMarkedForDeletion := syscallCounter.GetDeletionTimestamp() != nil
	if isMarkedForDeletion {
		logger.Info("SyscallCounter marked for deletion")
		return ctrl.Result{}, nil
	}

	// 3. Load eBPF objects
	objs := &bpf.BpfObjects{}
	err = bpf.LoadBpfObjects(objs, nil)
	if err != nil {
		// TODO: what is missing BTF info?
		if strings.Contains(err.Error(), "BTF") || strings.Contains(err.Error(), "CONFIG_DEBUG_INFO_BTF") {
			logger.Error(err, "Failed to load eBPF objects due to missing BTF info", "detail", err.Error())
			return ctrl.Result{}, fmt.Errorf("kernel BTF info missing or disabled: %w", err)
		}
		logger.Error(err, "Failed to load eBPF objects during bpf.LoadBpfObjects")
		return ctrl.Result{}, err
	}
	defer objs.Close()
	logger.Info("Successfully loaded eBPF objects")

	// 4. Get the target syscall
	targetSyscallName := syscallCounter.Spec.Syscall
	syscallNr, err := getSyscallNr(targetSyscallName)
	if err != nil {
		logger.Error(err, "Invalid syscall name specified in spec")
		return ctrl.Result{}, err // Do not requeu
	}
	logger.Info("Targetting syscall", "name", targetSyscallName, "number", syscallNr)

	// 5.Update eBPF Config Map
	// Key 0 corresponds to the single entry in our config_map array
	configKey := uint32(0)
	configValue := bpf.BpfConfig{TargetSyscallNr: syscallNr}
	err = objs.ConfigMap.Update(configKey, &configValue, ebpf.UpdateAny)
	if err != nil {
		logger.Error(err, "Failed to update eBPF Config Map")
		return ctrl.Result{}, err
	}
	logger.Info("Successfully updated eBPF config map")

	// 6. Attach eBPF program to Tracepoint
	// Attach to the "raw_syscalls/sys_enter" tracepoint where our SEC specifies
	tpLink, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		logger.Error(err, "Failed to attach tracepoint")
		return ctrl.Result{}, err
	}
	// Ensure the link is closed to detach the program
	defer tpLink.Close()
	logger.Info("Successfully attached eBPF program to tracepoint")

	// 7. Read Counter Map periodically
	// For a simple periodic update, we just read it once per reconcile and requeue after a delay.
	var totalCount uint64
	var perCpuCount []uint64
	counterKey := uint32(0)
	// Iterate over possible logical CPUs and sum up the counts.
	// objs.CounterMap should be the generated map handle.
	/*	iter := objs.CounterMap.Iterate()
		for iter.Next(&counterKey, &perCpuCount) {
			totalCount += perCpuCount
		}
		err = iter.Err()
		if err != nil {
			logger.Error(err, "Failed reading per CPU counter map")
			return ctrl.Result{}, err
		}*/
	err = objs.CounterMap.Lookup(&counterKey, &perCpuCount)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.Info("Counter map key does not exist", "key", counterKey)
			// Set total count to 0
			totalCount = 0
		} else {
			return ctrl.Result{}, err
		}
	} else {
		// Sum the values from all CPUs
		for _, count := range perCpuCount {
			totalCount += count
		}
	}
	logger.Info("Read counter value", "totalCount", totalCount)

	// 8. Update Status
	if syscallCounter.Status.Count != int(totalCount) {
		logger.Info("Attempting to update status...")
		syscallCounter.Status.Count = int(totalCount)
		err = r.Status().Update(ctx, syscallCounter)
		if err != nil {
			logger.Error(err, "Failed to update SyscallCounter status")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully updated status", "count", totalCount)
	} else {
		logger.Info("Status count already up-to-date", "current", syscallCounter.Status.Count)
	}

	// 9. Requeue periodically
	requeuDelay := 5 * time.Second
	logger.Info("Requeueing for next status check", "delay", requeuDelay)
	return ctrl.Result{RequeueAfter: requeuDelay}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SyscallCounterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&syscallcounterv1alpha1.SyscallCounter{}).
		Named("syscallcounter").
		Complete(r)
}

// Simple map for common syscalls (x86_64). Expand as needed.
var syscallNameToNr = map[string]uint64{
	"read":           0,
	"write":          1,
	"open":           2,
	"close":          3,
	"stat":           4,
	"fstat":          5,
	"lstat":          6,
	"poll":           7,
	"lseek":          8,
	"mmap":           9,
	"mprotect":       10,
	"munmap":         11,
	"brk":            12,
	"rt_sigaction":   13,
	"rt_sigprocmask": 14,
	"rt_sigreturn":   15,
	// ... network ...
	"socket":      41,
	"connect":     42,
	"accept":      43,
	"sendto":      44,
	"recvfrom":    45,
	"sendmsg":     46,
	"recvmsg":     47,
	"shutdown":    48,
	"bind":        49,
	"listen":      50,
	"getsockname": 51,
	"getpeername": 52,
	"socketpair":  53,
	// ... process ...
	"clone":  56,
	"fork":   57,
	"vfork":  58,
	"execve": 59,
	"exit":   60,
	"wait4":  61,
	"kill":   62,
	"uname":  63,
	// ... filesystem ...
	"openat":          257,
	"mkdirat":         258,
	"mknodat":         259,
	"fchownat":        260,
	"futimesat":       261,
	"newfstatat":      262,
	"unlinkat":        263,
	"renameat":        264,
	"linkat":          265,
	"symlinkat":       266,
	"readlinkat":      267,
	"fchmodat":        268,
	"faccessat":       269,
	"pselect6":        270,
	"ppoll":           271,
	"unshare":         272,
	"set_robust_list": 273,
	"get_robust_list": 274,
	"splice":          275,
	"tee":             276,
	"sync_file_range": 277,
	"vmsplice":        278,
	"move_pages":      279,
}

func getSyscallNr(name string) (uint64, error) {
	nr, ok := syscallNameToNr[strings.ToLower(name)]
	if !ok {
		return 0, fmt.Errorf("unknown syscall name: %s", name)
	}
	return nr, nil
}
