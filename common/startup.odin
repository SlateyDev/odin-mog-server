package common

import "core:fmt"

print_logo :: proc() {
	os_config()

	fmt.println(string(#load("logo.txt")))
}
