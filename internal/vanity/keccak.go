package vanity

import "math/bits"

func keccak256(in []byte, out *[32]byte) {
	var st [25]uint64
	const rate = 136
	for len(in) >= rate {
		xorLanes(&st, in[:rate])
		keccakF(&st)
		in = in[rate:]
	}
	var block [rate]byte
	copy(block[:], in)
	block[len(in)] ^= 0x01
	block[rate-1] ^= 0x80
	xorLanes(&st, block[:])
	keccakF(&st)
	for i := 0; i < 4; i++ {
		v := st[i]
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(v)
			v >>= 8
		}
	}
}

func xorLanes(st *[25]uint64, block []byte) {
	n := len(block) / 8
	for i := 0; i < n; i++ {
		var v uint64
		base := i * 8
		for j := 0; j < 8; j++ {
			v |= uint64(block[base+j]) << (8 * j)
		}
		st[i] ^= v
	}
	if rem := len(block) % 8; rem != 0 {
		var v uint64
		base := n * 8
		for j := 0; j < rem; j++ {
			v |= uint64(block[base+j]) << (8 * j)
		}
		st[n] ^= v
	}
}

func keccakF(a *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		for i := 0; i < 5; i++ {
			bc[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				a[j+i] ^= t
			}
		}
		t := a[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = a[j]
			a[j] = bits.RotateLeft64(t, rotc[i])
			t = bc[0]
		}
		for j := 0; j < 25; j += 5 {
			var tmp [5]uint64
			for i := 0; i < 5; i++ {
				tmp[i] = a[j+i]
			}
			for i := 0; i < 5; i++ {
				a[j+i] ^= (^tmp[(i+1)%5]) & tmp[(i+2)%5]
			}
		}
		a[0] ^= rc[round]
	}
}

var rc = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var rotc = [24]int{
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
}

var piln = [24]int{
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
}
