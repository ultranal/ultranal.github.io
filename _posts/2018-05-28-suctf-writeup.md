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
这是一道Misc题，但由于涉及了数论知识，故写在Crypto里。

game.py

    #!/usr/bin/env python
    # -*- encoding: utf-8 -*-

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

* 一元线性同余方程组

$$\begin{aligned}\
(\mathbf{S}) : \quad \left\{ \begin{matrix} x \equiv a_1 \pmod {m_1} \\ x \equiv a_2 \pmod {m_2} \\ \vdots \qquad\qquad\qquad \\ x \equiv a_n \pmod {m_n} \end{matrix} \right.
\end{aligned}
$$

有解，当且仅当其所有模数\\(m_1, m_2, \ldots, m_n\\)互质（这里的S式符合这个条件）；

* 记\\(M=\prod_{i=1}^{n} m_i\\)，\\(M_i = M / m_i\\)，\\(t_i\\)为\\(M_i\\)的模逆元，则S的解符合以下公式：

$$
\begin{aligned}
x \equiv \sum_{i_1}^{n} a_it_iM_i \pmod{M}
\end{aligned}
$$

讲到这里，就不得不提一下[模逆元](https://zh.wikipedia.org/wiki/%E6%A8%A1%E5%8F%8D%E5%85%83%E7%B4%A0)的概念：整数a在模N意义下的模逆元是指满足以下公式的整数b：

$$
\begin{aligned}
a^{-1} \equiv b \pmod{N}
\end{aligned}
$$

模逆元仅在a和N互质的情况下存在。换言之，在模N的意义下，**对a的除法可以通过和a的模逆元b的乘法来达成**（RSA一题的主要原理）。

求模逆元使用[扩展欧几里得算法](https://zh.wikipedia.org/wiki/%E6%89%A9%E5%B1%95%E6%AC%A7%E5%87%A0%E9%87%8C%E5%BE%97%E7%AE%97%E6%B3%95)（欧几里得算法就是辗转相除法）来实现。

    #!/usr/bin/env python
    # -*- encoding: utf-8 -*-
    
    def extended_eucild(a, b):
        if b == 0:
            return a, 1, 0
        d, x, y = extended_eucild(b, a % b)
        x, y = y, x - a / b * y
        return d, x, y

说了这么多，本题的解法就是通过扩展欧几里得算法求解上文给定的一元线性同余方程组S：

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

> flag{This_is_the_CRT_xwg)}

### RSA good
题目给定了N和e
    
    N = 342455709448748144126356744976385170973517744602059517490422045682543287960167955127769980654250125331171261846920903825693509591867402054748269545989173880386620770767057995165518626234085821335790902075953939551116777613078301529741199260825495593643848062203477826484698214686522001924292713782595019038086926834360866522789951283935502968545347160597915951673480253253216027297476774028106074570088497425654525031294571609018030761716007610673627163536370205798268831577480146622906265953470659107801115278898533958878045433701201601516984582294147038705649395688342773971893457527598221773710752744142729023770679
    e = 65537

注意到，给定的N具有[已知的质因数分解](http://factordb.com/index.php?query=342455709448748144126356744976385170973517744602059517490422045682543287960167955127769980654250125331171261846920903825693509591867402054748269545989173880386620770767057995165518626234085821335790902075953939551116777613078301529741199260825495593643848062203477826484698214686522001924292713782595019038086926834360866522789951283935502968545347160597915951673480253253216027297476774028106074570088497425654525031294571609018030761716007610673627163536370205798268831577480146622906265953470659107801115278898533958878045433701201601516984582294147038705649395688342773971893457527598221773710752744142729023770679)：

    3424557094...79<618> = 7 · 4892224420...97<617>

则p = 7, q = 4892224420...97。计算可得r, d = 1170425334...09。
 
利用[rsatool](https://github.com/ius/rsatool)创建PEM格式的私钥，通过openssl rsautil 解密给定密文：

     $ python rsatool.py -f PEM -o key.pem -n 3424557094...79 -d 1170425334...09
     $ openssl rsautl -decrypt -in pp.txt -inkey key.pem -out ppp.dec -raw

得到flag:

> SUCTF{Ju5t_hav3_fun_1n_R34_4Ga1N!}

### RSA
    #!/usr/bin/env python
    # -*- encoding: utf-8 -*-

    from Crypto.Random import random
    import binascii
    import hashlib

    def invmod(a, n):
        t = 0
        new_t = 1
        r = n
        new_r = a
        while new_r != 0:
            q = r // new_r
            (t, new_t) = (new_t, t - q * new_t)
            (r, new_r) = (new_r, r - q * new_r)
        if r > 1:
            raise Exception('unexpected')
        if t < 0:
            t += n
        return t

    smallPrimes = [2, 3, 5, 7, 11, 13, 17, 19]

    def primefactor(p):
        for x in smallPrimes:
            if p % x == 0:
                return True
        return False

    def isprime(p, n):
        for i in range(n):
            a = random.randint(1, p)
            if pow(a, p - 1, p) != 1:
                return False
        return True

    def getprime(bit):
        while True:
            p = random.randint(2**(bit - 1), 2**bit - 1)
            if not primefactor(p) and isprime(p, 5):
                return p

    def genKey(keybits):
        e = 3
        bit = (keybits + 1) // 2 + 1

        p = 7
        while (p - 1) % e == 0:
            p = getprime(bit)

        q = p
        while q == p or (q - 1) % e == 0:
            q = getprime(bit)

        n = p * q
        et = (p - 1) * (q - 1)
        d = invmod(e, et)
        pub = (e, n)
        priv = (d, n)

        return (pub, priv)



    pub, priv = genKey(2048)
    (e,n) = pub
    (d,n) = priv
    de_hash = set()



    def b2n(s):
        return int.from_bytes(s, byteorder='big')

    def n2b(k):
        return k.to_bytes((k.bit_length() + 7) // 8, byteorder='big')

    def decrypt(cipher):
        md5 = hashlib.md5()
        md5.update(cipher)
        digest = md5.digest()
        if digest in de_hash:
            raise ValueError('Already decrypted')
        de_hash.add(digest)
        return n2b(pow(b2n(cipher), d, n))

    if __name__ == '__main__':
        plain = 
        cipher = n2b(pow(b2n(plain), e, n))
        r = random.randint(2, n - 1)
        c = b2n(cipher)
        c2 = (pow(r, e, n) * c) % n
        print (e)
        print (d)
        print (c2,r,n)
    
解读代码，可以看见生成了随机值r,将r和flag分别加密后密文值相乘为c2。给定d, e, c2, r, N，求解flag。

换言之：

$$
\begin{aligned}
    flag^e \cdot r^e \equiv c_2 \pmod{N}
\end{aligned}
$$

考虑到上文[模逆元](https://zh.wikipedia.org/wiki/%E6%A8%A1%E5%8F%8D%E5%85%83%E7%B4%A0)的定义：

$$
\begin{aligned}
    c_2^d \equiv flag \cdot r \pmod{N}
    flag \equiv r^-1 \pmod{N}
\end{aligned}
$$

flag*r的值可以通过openssl rsautil解密获得。

问题即转化为求r对N的模逆元。注意，由于N, r较大，这里的扩展欧几里得算法需要用递推实现：

    #!/usr/bin/env python
    # -*- encoding: utf-8 -*-

    rmuln = 59115915707374791858043439923167683347161887030487325917423499796492203695323206558401630102578799900218436597230954437778111746830394958514693795703668608134688484361451977542361964879441862660907225537016230464396774501614633550453344389997701652088926779491939154277967969883770814387902879875613743223229395914926347385430187855896072954220734275197088587384423545384415702580062626846187660369433673963925368283292589562338733264483707085154679553150155966218540039768554264425242930122630759578034001784040206494331067331934081888223924875304452399021658433028042708859136403044098846651745078168587090692758339
    N = 114074818133739504250047209185005541235104076834407454843024262517200619155182936436785962918603977053600646077595890908700137268868699889055060972806312126948522642693058329618120858621695314653366215387973749480530773400994063166095532724955861880985112526415669572580061355860224679573858183474455325088556643994673345465994162610420723170253345262031304174343327749668957998269532265104735742501097132399909676529715137398930849255495327761212026819673358330120772259339210848101393790624794141497382162858696771273350710124735773784422786465775396114824753700050260926501450377050949467981761553058188615697572753
    r = 52590127432976083491238732503614965276544329818688634632767137973918045578992812985289716736906703169505549436697176020030544816837575642406120330044094101926756390272838108002439881182112360442668104629856258556842855755302886464339208354825118921549697616322247157559049488040135615532105368336491021854265473475528069047122826089655385379767218204046669380406790462989897640184187821995434927599001724468830237117370372883192568919508659630357441363324857869183828526986625221594440014568348246392587406204121296464310150086319496345975298783813760793880968818397424849582987543667279959113716063661758542453795636
    k = 0


    def extended_eucild(a, b):
        p = []
        if b == 0:
            return a, 1, 0
        while b != 0:
            p.append((a, b))
            a, b = b, a % b
        x, y = 1, 0
        while len(p) > 0:
            a, b = p.pop()      
            x, y = y, x - a / b * y
        return x, y
        
        
    if __name__ == "__main__":    
        x, y = extended_eucild(r, N)        
        t = (x * rmuln) % N
        print ("%x" % t).decode('hex')
