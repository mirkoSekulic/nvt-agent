package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	nvtv1alpha1 "github.com/mirkoSekulic/nvt-agent/operator/api/v1alpha1"
	"github.com/mirkoSekulic/nvt-agent/operator/internal/controller"
)

var scheme = runtime.NewScheme()

func registerSchemes() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(nvtv1alpha1.AddToScheme(scheme))
}

func main() {
	registerSchemes()

	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var callbackAddr string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&callbackAddr, "callback-bind-address", ":8082", "The address the AgentRun callback endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Cache:                  managerCacheOptions(),
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "agentrun-operator.nvt.dev",
	})
	if err != nil {
		ctrl.Log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.AgentRunReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create controller", "controller", "AgentRun")
		os.Exit(1)
	}
	if err = (&controller.AgentScheduleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create controller", "controller", "AgentSchedule")
		os.Exit(1)
	}
	if err = mgr.Add(callbackServer(callbackAddr, operatorHTTPHandler(mgr))); err != nil {
		ctrl.Log.Error(err, "unable to add operator HTTP server")
		os.Exit(1)
	}

	if err = mgr.AddHealthzCheck("healthz", func(_ *http.Request) error { return nil }); err != nil {
		ctrl.Log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("readyz", func(_ *http.Request) error { return nil }); err != nil {
		ctrl.Log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	ctrl.Log.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func managerCacheOptions() cache.Options {
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		return cache.Options{}
	}
	return cache.Options{
		DefaultNamespaces: map[string]cache.Config{
			namespace: {},
		},
	}
}

func operatorHTTPHandler(mgr manager.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/agentruns/", controller.NewAgentRunCallbackHandler(mgr.GetClient()))
	mux.Handle("/v1/schedules/", controller.NewAgentScheduleAdmissionHandler(mgr.GetClient(), mgr.GetScheme()))
	return mux
}

func callbackServer(addr string, handler http.Handler) manager.Runnable {
	shutdownTimeout := 10 * time.Second
	return &manager.Server{
		Name: "agentrun-callbacks",
		Server: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
		},
		ShutdownTimeout: &shutdownTimeout,
	}
}
