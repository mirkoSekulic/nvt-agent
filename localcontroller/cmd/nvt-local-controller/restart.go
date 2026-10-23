package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/mirkoSekulic/nvt-agent/localcontroller/internal/controller"
)

func restartClient(args []string) int {
	if len(args) != 3 || args[0] != "restart-workstation" {
		fmt.Println("invalid-request")
		return 1
	}
	timeout, err := time.ParseDuration(args[2])
	if err != nil || timeout < time.Second || timeout > 15*time.Minute {
		fmt.Println("invalid-request")
		return 1
	}
	bind := os.Getenv("NVT_LOCAL_CONTROLLER_BIND")
	if bind == "" {
		bind = "0.0.0.0:7480"
	}
	_, port, err := net.SplitHostPort(bind)
	number, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || number < 1 || number > 65535 {
		fmt.Println("unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result := controller.RestartAndWait(ctx, "http://127.0.0.1:"+port, os.Getenv("NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE"), args[1])
	fmt.Println(result)
	if result == "ready" {
		return 0
	}
	return 1
}
