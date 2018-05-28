---
layout: post
title: SUCTF 2018 Write-up
date: 2018-05-28 15:28:53.000000000 +08:00
tags: writeup
---

1. 还是先写最近的……否则真的容易忘
2. 想交个wp从来都没资格


## Crypto & Misc
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

类似这样的方程组，在数论中称作一元线性**同余方程组**。著名的[**中国剩余定理**](https://zh.wikipedia.org/wiki/%E4%B8%AD%E5%9B%BD%E5%89%A9%E4%BD%99%E5%AE%9A%E7%90%86)描述了该类方程有解的判定条件及其解法：

1. 一元线性同余方程组

$$\begin{aligned}\
(\mathbf{S}) : \quad \left\{ \begin{matrix} x \equiv a_1 \pmod {m_1} \\ x \equiv a_2 \pmod {m_2} \\ \vdots \qquad\qquad\qquad \\ x \equiv a_n \pmod {m_n} \end{matrix} \right.
\end{aligned}
$$

有解，当且仅当其所有模数\\(m_1, m_2, \ldots m_n\\)互质；
2. 记\\(M_i\\)为\\(m_i\\)以外所有模数的乘积，\\(t_i\\)为\\(M_i\\)的模逆元，则S的解符合以下公式：

$$
\begin{aligned}
x \equiv \sum_{i_1}^{n} a_it_iM_i \pmod{M}
\end{aligned}
$$

讲到这里，就不得不提一下[模逆元](https://zh.wikipedia.org/wiki/%E6%A8%A1%E5%8F%8D%E5%85%83%E7%B4%A0)的概念：整数a在模N意义下的模逆元是指满足以下公式的整数b：
$$
a^{-1} \equiv b \pmod{N}
$$

模逆元仅在a和N互质的情况下存在。换言之，在模N的意义下，**对a的除法可以通过和a的模逆元b的乘法来达成**（RSA一题的主要原理）。

求模逆元使用扩展欧几里得算法（欧几里得算法就是辗转相除法）来实现。

    def extended_eucild(a, b):
    if b == 0:
        return a, 1, 0
    d, x, y = extended_eucild(b, a % b)
    x, y = y, x - a / b * y
    return d, x, y

说了这么多，本题的解法就是通过扩展欧几里得算法求解上文给定的一元线性同余方程组X：

    #!/usr/bin/env python
    # -*- encoding: utf-8 -*-

    a = [222, 203, 33, 135, 203, 62, 227, 82, 239, 82, 11, 220, 74, 92, 8, 308, 195, 165, 87, 4]
    w = [257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373]

    def extended_eucild(a, b):
        if b == 0:
            return a, 1, 0
        d, x, y = extended_eucild(b, a % b)
        x, y = y, x - a / b * y
        return d, x, y

    def crt(a, w):
        ret = 0
        n = 1
        for i in w:
            n *= i
        for i in range(len(w)):
            m = n / w[i]
            d, x, y = extended_eucild(w[i], m)
            ret = (ret + y * m * a[i] % n) % n
        return ret
        
    if __name__ == "__main__":
        print hex(crt(a, w))[2:-1].decode('hex')

