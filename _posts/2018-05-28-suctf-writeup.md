---
layout: post
title: SUCTF 2018 Write-up
date: 2018-05-28 15:28:53.000000000 +08:00
tags: writeup
---

1. 还是先写最近的……否则真的容易忘
2. 想交个wp从来都没资格


## Crypto
这次SUCTF算是好好的复习了一下数论（明明本来就很简单）。
然而为什么这么多数学公式……排个版真难

### SandGame
数论题，使用中国剩余定理可解。

game.py

    import flag

    flag = flag.flag
    sands = int(flag[5:-1].encode("hex"), 16)

    holes = [257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373]

    with open("sand.txt", "w") as f:
        for i in range(len(holes)):
            sand = sands % holes[i]
            f.write(str(sand)+"\n")

sand.txt

    222
    203
    33
    135
    203
    62
    227
    82
    239
    82
    11
    220
    74
    92
    8
    308
    195
    165
    87
    4

这段代码加上sand.txt给出来的解，实际上构成了下面的同余方程组：

$$
\begin{aligned}
    n \equiv 222 \pmod{257}\\
    n \equiv 203 \pmod{263}\\
    n \equiv 33 \pmod{269}\\
    n \equiv 135 \pmod{271}\\
    n \equiv 203 \pmod{277}\\
    n \equiv 62 \pmod{281}\\
    n \equiv 227 \pmod{283}\\
    n \equiv 82 \pmod{293}\\
    n \equiv 239 \pmod{307}\\
    n \equiv 82 \pmod{311}\\
    n \equiv 11 \pmod{313}\\
    n \equiv 220 \pmod{317}\\
    n \equiv 74 \pmod{331}\\
    n \equiv 92 \pmod{337}\\
    n \equiv 8 \pmod{347}\\
    n \equiv 308 \pmod{349}\\
    n \equiv 195 \pmod{353}\\
    n \equiv 165 \pmod{359}\\
    n \equiv 87 \pmod{367}\\
    n \equiv 4 \pmod{373}
\end{aligned}
$$
