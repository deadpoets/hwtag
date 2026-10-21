package main

import (
	"fmt"
	"time"

	"github.com/foxboron/age-plugin-tpm/ykpiv"
)

func main() {
	yk, err := ykpiv.OpenCard(0)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer yk.Close()
	slot, _ := ykpiv.SlotFor(0x82)
	_, err = yk.KeyInfo(slot)
	fmt.Println("keyinfo t=0:", err)
	for _, d := range []int{2, 5, 15} {
		time.Sleep(time.Duration(d) * time.Second)
		_, err = yk.KeyInfo(slot)
		fmt.Printf("keyinfo after +%ds idle: %v\n", d, err)
	}
}
