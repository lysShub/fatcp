fatcp已经无太大价值：
    建立一个握手可靠，数据包传输的连接，没有太大作用；欺骗性上，可以直接用原始tcp连接发送pss，可能针对udp被严重QOS的情况下有些用，而且会受到传输层转发的影响（因为有个握手过程，需要根据从tcp头重区分是不是fake包，传输层转发会影响tcp头，导致协议不能正常工作；经典的fake-tcp完全忽略了tcp头，影响会减小些）。

    它太复杂了！！！！

    这一切基于“tcp串联会影响流控”的假设；但是基于这个假设应该是一个基于DGRM的连接。至于安全完全交割builtin-session，代码上builtin-session 和其他session有先后，只不过通常，只有builtin-session 完成安全相关的工作后才能开始其他session。
    

    我们可以用更加简单的方式实现fatcp的功能：
    先和代理服务器建立普通tcp，然后在这个普通tcp上完成pss、验证等操作；然后“静默关闭”这个tcp（在linux上可能复杂些，tun可以做到）；然后再启动经典fake-tcp，在这个经典tcp上进行任何后续操作。        




# fatcp
 
  datagram transport connect on tcp, provide crypto option and builtin tcp.



todo: rawsocket support deadline, open Test_Handshake_Context_Cancel


