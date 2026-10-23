# DH CTF - reversing challenge
# 코드를 직접 실행하기보다 각 연산을 따라가며 check 값을 계산하세요.

seed = 11
a = (seed * 7) + 5
b = a ^ 0x1F
c = (b << 2) - 9
d = (c // 5) + 14
e = (d * 3) ^ 0x2A
check = (e % 1000) + 17

print(check)
# Flag format: DH{숫자}
