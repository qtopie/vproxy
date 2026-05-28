package main
import (
	"fmt"
	"os"
)
func main() {
	pid := os.Getppid()
	procsFile := "/sys/fs/cgroup/vproxy/cgroup.procs"
	err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0644)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Successfully moved parent PID", pid, "to vproxy cgroup")
	}
}
