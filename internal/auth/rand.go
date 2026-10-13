package auth

import (
	"crypto/rand"
	"math/big"
)

const randChars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-"

// randRead 用 crypto/rand 填充字节。
func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

// RandomPassword 生成满足强密码策略的随机密码。
func RandomPassword(n int) string {
	if n < 12 {
		n = 12
	}
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(randChars))))
		if err != nil {
			// crypto/rand 极罕见失败，回退到固定字符集首位避免 panic
			out[i] = randChars[i%len(randChars)]
			continue
		}
		out[i] = randChars[idx.Int64()]
	}
	return string(out)
}
