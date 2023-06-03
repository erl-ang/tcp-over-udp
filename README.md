# tcp-over-udp
name, uni: Erin Liang, ell2147

A simplified version of the transmission control protocol (TCP) that operates over user datagram protocol (UDP) in order to provide reliable data delivery. To simulate a unreliable network, we use [newudpl from the Columbia Internet and Real Time Lab](http://www.cs.columbia.edu/~hgs/research/projects/newudpl/newudpl-1.4/newudpl.html). 

Made for Professor Misra's Spring 2023 CSEE W4119 Computer Networks course at Columbia University. The [original spec can be found here](https://github.com/erl-ang/tcp-over-udp/blob/master/Programming%20Assignment%202.pdf).

## Overview 🏘️
TCP and UDP are protocols used in computer networks for communication between devices. TCP ensures reliable data delivery, meaning it guarantees that data is received in the correct order and without errors. On the other hand, UDP does not provide these guarantees, and packets can arrive out of order or even be lost.

To understand TCP's reliability mechanisms better, we can implement similar mechanisms on top of UDP. However, testing these mechanisms locally is challenging because the data packets are unlikely to be dropped or corrupted in a local network.

To overcome this challenge, we can use a network emulator, `newudpl`, as a proxy between the client and the server. This allows us to test our TCP implementation and see if it behaves as expected under various network conditions.

<p align="center"><img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/proxy.png" style="width: 70%;"></p>

Note that in this assignment, ACKs were assumed to be reliable (i.e. ACKs do not go through `newudpl`), which is not a realistic assumption.

## How to Run 🏃
### Eunning `newudpl`

If you cannot run the provided `newudpl` binary directly, build it from the provided `.tar` file:
```bash
tar -xf newudpl-1.7.tar
cd newudpl-1.7.tar
./configure
make
```

Example `newudpl` command (recreating diagram above):
- Running `newudpl` that listens for client’s messages on port 2222 and forwards messages to port 4444. Both the client and server program are run on the local machine. The probability of packets being dropped is 50%. Oof.
```bash
./newudpl -p 2222:3333 -i 127.0.0.1:1234 -o 127.0.0.1:4444 -vv -L50
```
- For more help on how to run `newudpl`, see [this link](http://www.cs.columbia.edu/~hgs/research/projects/newudpl/newudpl-1.4/newudpl.html)

### Running `tcpclient.py` 💻

Generically, the usage of `tcpclient` is:

```bash
$ python3 tcpclient.py -h
usage: tcpclient.py [-h] file address_of_udpl port_number_of_udpl windowsize ack_port_number

Bootleg TCP implementation over UDP

positional arguments:
  file                 file that client reads data from
  address_of_udpl      emulator's address
  port_number_of_udpl  emulator's port number
  windowsize           window size in bytes
  ack_port_number      port number for ACKs

optional arguments:
  -h, --help           show this help message and exit
```

To run the client, an example command is:

```bash
python3 tcpclient.py ./testfiles/screendump.txt 0.0.0.0  2222 1152 1234
```

- This will start running a tcpclient that listens on port 1234 for ACKs and wants to send `screendump.txt`. The tcpclient will forward all segments it needs to send to the server to `newudpl`, which is listening on address (0.0.0.0, 2222). The tcp `windowsize` is set to 1152.

### Running `tcpserver.py`  💻

Generically, the usage of `tcpserver` is:
```bash
$ python3 tcpserver.py -h
usage: tcpserver.py [-h] file listening_port address_for_acks port_for_acks

Bootleg TCP implementation over UDP

positional arguments:
  file              file to send over TCP
  listening_port    port to listen on
  address_for_acks  address to send ACKs to
  port_for_acks     port to send ACKs to

optional arguments:
  -h, --help        show this help message and exit
```

To run the server, an example command is:

```bash
python3 tcpserver.py ./testfiles/screendump.txt  4444 127.0.0.1 1234
```

- This will start running a tcpserver listening on port 4444 locally. It will receive `screendump.txt` and acknowledge receipt of tcp segments by sending ACKs to the client’s address (port 1234 locally)
- Note that `(address_for_acks, port_for_acks)` is the client’s address. 


## Project Files 🗄️
```
├── tcp-over-udp
   ├── README.md <-- You're here now!
   ├── utils.py
   ├── tcpserver.log
   ├── tcpclient.log
   ├── tcpserver_debug.log
   ├── tcpclient_debug.log
   ├── tcpclient.py
   └── tcpserver.py
 ```

| Filename                       | Description                                                                                     
|--------------------------------|------------------------------------------------------------------------------------------                             
| `README.md`                   | Describes program, program usage, design tradeoffs, internal workings, etc.                                       
| `utils.py`                     | Tools used in both tcpclient and tcpserver, e.g. tcp header creation, checksum calculations, timeout EWMA weights.       
| `tcpserver.log`,`tcpclient.log`| Screendump of a typical client-server interaction.                     
| `tcpserver_debug.log`          | See above, but with more robust logging.
| `tcpclient_debug.log`          | See above.                
| `tcpclient.py`                 | Contains all the code for client functionality.                                        
| `tcpserver.py`                 | Contains all the code for server functionality. 

## Features
The file sharing system implements:
- Connection establishment via the three-way handshake
- Reliable transmission of a file
- Connection teardown via sending a FIN (where either the client and server can initiate)
- Retransmission timer adjustment
- Logging

You can adjust some of the TCP variables set in `utils.py` to test what yields the best performance. These variables are:

- `MSS`, the maximum amount of data that can be carried in a single TCP segment.
- `MAX_RETRIES` , the maximum amount of retries the programs try to send a segment before initiating the connection teardown sequence (i.e. sending a FIN to to the client/server)
- the retransmission and timeout constants: `INITIAL_TIMEOUT`, `ALPHA`, `BETA`, `TIME_WAIT`,and `TIMEOUT_MULTIPLIER`. These values are discussed in the design doc

Note that adjusting these variables comes at your own risk. No matter what, the connection is guaranteed to terminate gracefully (but not always efficiently). For example, if `MAX_RETRIES` is too low and there is significant packet loss, the client will probably hit the threshold for retransmissions and send a FIN to terminate the connection early. This is reasonable behavior because a client should probably wait for the network conditions to get better before trying to transmit a file.


## Normal Program Run
*A description of a successful file transfer between the client and the server. Other cases are discussed later in this document*

After successfully running udpl, tcpserver, and tcpclient, the following actions will occur...
- three way handshake to establish the connection,
- the actual data transfer,
- and connection teardown,
- with retransmission timers being adjusted in between!

## How it Works
### Establishing a connection 🤝

The information in this section is derived from K&R pg249. In TCP, which is a connection-oriented protocol, two processes intending to communicate with each other need to establish a connection through a procedure known as the three-way handshake. The steps involved in the connection-establishment procedure are as follows:

<p align="center">
  <img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/connection-est.png">
</p>

1. The client process initiates by first sending a SYN with a random `client_isn` in the seq_num in the segment to the server.
2. After receiving the SYN, the server will respond with SYNACK segment to indicate that it has agreed to establish this connection. This SYNACK has `client_isn+1` in the header’s ack field, and puts its own initial random sequence number `server_isn` in the seq num.
3. After the client has received the SYNACK segment, the client will send a final segment to complete the connection-establishment procedure. This final ACK segment is piggybacked on 4 bytes of data containing the file’s size.

This is the exchange if all goes well. But what happens if the SYN segment does not arrive?

#### Packet Loss During a Three-way Handshake
*As packet loss can occur during connection establishment, the following design decisions were made to avoid a half-open connection for a prolonged period of time.*

**Losing SYN packet:**
- Following [this Ed thread](https://edstem.org/us/courses/36439/discussion/2979548), the client will try sending the SYN segment `MAX_RETRIES` amount of times until it receives an SYNACK with the `client_isn+1`, adjusting the timeout according to the TCP standard.
- If the client doesn’t receive that SYNACK within `MAX_RETRIES` transmissions, it will abort the connection.
- The server will be listening for the SYN until it times out `MAX_RETRIES` times (adjusting the timeout according to the TCP standard), aborting the connection if it has.

**Losing the client’s final ACK:**

The client will send an ACK segment with the file size piggybacked to the server and wait for an ACK from the server before officially sending file data. 
- This ACK is treated like all other segments (retransmitted until it hits the limit). If the ACK is not ACK’d back within the retransmission limit, the client will send a FIN and the server will respond.
- This mechanism is to prevent a half-open connection if the last ACK of the three-way handshake gets lost. While the server will timeout waiting for its SYNACK to be ACK'd, the client will think that the connection is established and start sending data. By waiting for an additional ACK, we can ensure that the connection is fully established before sending file data.
- This is implemented in `SimplexTCPClient._send_ack_with_filesize`

### Data transmission and reception

#### Data transmission 🚀

The file is divided in (file size in bytes)/(MSS in bytes) number of segments, with each segment being of size $MSS$. Data transmission and reception is implemented in `SimplexTCPClient.send_file_gbn` and `SimplexTCPServer.receive_file_gbn`

The client will read $MSS$ data from the file at a time and send out (windowsize // MSS) packets. We keep track of the window’s packets and how many retries the packet has taken with a list of tuples to take valid $SampleRTT$ measurements.

```
# window format:
[(segment, num_retries), ...]
```
    
- We also keep track of `send_base` and `next_seq_num` for the window’s valid indices:
 
<p align="center">
  <img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/gbn-view.png">
</p>

One segment from the window will be chosen to measure a $SampleRTT$ for so we can update the timeout values. If the segment has been retransmitted, we discard the $SampleRTT$ and just have to live with the fact that we won’t have a $SampleRTT$ for this RTT.

Once the client has filled up its window, the client will try receiving ACKs, verifying if the ACK for a segment that is currently in the window. If it is, we can move the window forward by removing the segment from the window and updating the `send_base`.

To account for lost packets, if the client does not receive a valid ACK in time, it will timeout and retransmit all the segments in the window, incrementing the number of retransmissions that the segments have taken.

If a segment has been retransmitted too many times, it will begin the connection teardown sequence by sending a FIN to the server.

See the additional features section for fast transmit explanation.

#### Data reception 👐

All the data that the client sends will be written to a file called `recvd_file` so users can easily `diff` it with the original file. Data reception is implemented in `SimplexTCPServer.receive_file_gbn`.

The receiver will keep track of two state variables:

- `next_seq_num`, the next expected sequence number to receive next.
- the number of `bytes_received` so far from the client. This is used so the server can detect when we’re done transmitting

The server will open a new file called `recvd_file` for writing and try receiving data from the client, updating the timeout accordingly.

If the server receives something, the received segment can:

- be out of order or corrupted —> the packet is discarded and a duplicate ack is sent (ack with the last in-order packet correctly received)
- have the correct expected sequence number -> the ack for `next_seq_num` is sent and `next_seq_num` is incremented to denote that we received it (again, it’s the ack with the last in-order packet correctly received)

Terminating data reception:

- Case 1: The server has received the `filesize` bytes and will send a FIN to the client.
- Case 2: The server hits its retransmission limit and terminates prematurely. There is a check in `receive_file_gbn` to check if the server received a FIN segment, in which case it will begin the `_respond_to_fin()` sequence.

Note that the `seq_nums` of the TCPServer and the ack_nums of the TCPClient don’t have to be used because we’re using a GBN policy!

### Ending a connection (FIN request) 🏁

Both the server and the client are able to initiate the teardown sequence. This is implemented in both file’s `send_fin()`.

<p align="center">
  <img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/teardown.png">
</p>

The client will initiate the closing of a TCP connection when a segment hits its retransmission limit.

This can happen while 1) sending file data or 2) during the last ACK of the three way handshake. This sequence depicted by the K&R diagram above will be kicked off.
- The client will send a FIN (which can get lost). If the FIN segment hits the retransmission limit, there is nothing that the client can really do, so it just aborts and exits.
- If the server successfully receives the FIN, it will respond with a FINACK and then a FIN. After this point, the server can try to receive the ack and wait TIME_WAIT seconds before closing the connection. This is implemented in `respond_to_fin()`

The server will initiate the closing of a TCP connection when it has received the entire file from the client. This will kick off the same sequence as above, with the server and client’s roles reversed.
- The server will send a FIN to the client.
- The client will respond with a FINACK, which can get lost. The client will also respond with a FIN, which can also get lost. This is implemented in `respond_to_fin()`

### Error logging ⚠️

Python’s `logging` module is used to record timeouts, duplicate acks, retransmissions, and connection teardown/setup states with timestamps.

To get **more** verbose logging, you can set `LOGGING_LEVEL` in `utils.py` to `logging.DEBUG`. This may come at the expense of performance if the file is large and especially because the logs are being written to multiple streams.

To get **less** verbose logging, you can set LOGGING_LEVEL to `logging.INFO` , `logging.WARNING`, `logging.ERROR`, etc. Higher levels will include all the logs from the levels below. For example, INFO will include all the logging.error logs. See the documentation for Python’s logging module for more details.

| Level    | Description                                                                                                                                                                                                                   |
|----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DEBUG    | Lots of information: every packet and its `ack_num`, `seq_num`, payload, and flags; when a new sample RTT is measured / discarded when the packet being measured is a retransmission; window moving forward and which segment is being removed from it; the expected `ack_num` when a duplicate ack is received, etc. |
| INFO     | Timeout updates, states for connection teardown and establishment (e.g., `CLOSE_WAIT`, `SYN_SENT`, etc.), file transfer messages, out of order segments, etc.                                                                 |
| WARNING  | Maximum retransmissions reached —> beginning to terminate program, handling unexpected exceptions (haven't seen this one be invoked yet)                                                                                       |
| ERROR    | Checksum verification failures, unexpected flags in received segments, incorrect `ack` numbers during the handshake sequence, invalid arguments, etc.                                                                             |

- For convenience, logs are written to `tcpclient.log` , `tcpserver.log` , as well as `stdout`

### 20-byte TCP header format  💆‍♀️

The format of the TCP headers attached to the payload follows the below K&R diagram:

<p align="center">
  <img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/tcp-seg-structure.png">
</p>

The header is created in `_make_tcp_header_without_checksum` in utils, as we cannot compute the checksum without the segment’s payload.

There are some fields that are not used in this program (CWR, ECE, RST, urgent data pointer, options), so the implemented header looks like:

<p align="center">
  <img src="https://github.com/erl-ang/tcp-over-udp/blob/master/assets/implemented-tcp-structure.png">
</p>

### Retransmission timer adjustment as per TCP standard ⏳

Figuring out how long the timeout should be before a segment gets retransmitted is tough; it must be larger than the RTT, otherwise there would be too many retransmissions. But it can’t be too large, otherwise lost packets will not be quickly retransmitted.

The following statements document some design choices concerning the retransmission timer.

A maximum retransmission limit of 7 (can be tweaked in `utils`) was set because typical TCP implementations have a `MAX_RETRIES` of 5-7.

The socket timeouts are set via the below formulas taken from the textbook. These implementations can be found in the tcpclient and tcpserver’s `update_timeout_rtt()`

$$ TimeoutInterval = EstimatedRTT + 4DevRTT $$
- where EstimatedRTT and DevRTT are measures of the “average sampleRTT” and “ variability of the RTT” given by these formulas from RFC 6298:  

$$ EstimatedRTT = 0.875Estimated RTT + 0.125SampleRTT $$   
$$ DevRTT = 0.75DevRTT + 0.25|SampleRTT - EstimatedRTT|$$  
- the $EstimatedRTT$ formula is a weighted combination of the previous value of $EstimatedRTT$ and $SampleRTT$ from RFC 6298. The motivation behind using an “average” is that $SampleRTT$'s vary a lot with network congestion and fluctuations.

Like most other TCP implementations, we only take a `SampleRTT` measurement for only *one of the transmitted but UNACK’d segments*. We only really need a new value of $SampleRTT$ per RTT; it is unnecessary and slows down things if we take any more measurements.

The client does not compute $SampleRTT$ for retransmissions, as the client cannot distinguish between an ACK for the original segment vs an ACK for a retransmitted segment. Measuring RTTs for retransmissions could cause a huge dip in the $SampleRTT$ and lead to even faster transmissions, jamming the network more.
- Performance note: when there’s a lot of loss (e.g. L50), it takes a longer time to send (as expected) because the SampleRTTs aren’t updating on a per-RTT basis since there’s more retransmissions.

Per RFC 6298, the initial $timeoutInterval$ value is set to 1 second. Upon receipt of the first valid ACK, the $EstimatedRTT$ is initialized to $SampleRTT$, and $DevRTT=0.5*SampleRTT$. We start trying to measure valid ACKs in the connection setup sequence.

I chose to not do any adjusting for the $SampleRTT$ in the FIN sequence, as the connection is shutting down.

Note that the server cannot measure as many $SampleRTTs$ as the client, as it does not send data and wait for ACKs often. It only waits for a segment’s ACK during connection setup and teardown, but I chose to only attempt to measure a $SampleRTT$ during connection setup as having an accurate timeout value during teardown is not of the highest priority. If this $SampleRTT$ was not representative of the actual average RTT of the server → receiver link, this decision could cause lots of timeouts.

### Correct computation of the TCP checksum ✅

The checksum is calculated in `calculate_checksum` and attached to the segment in`make_tcp_segment`

The process is as follows:
- make sure the segment’s length is even. if not, pad a 0-byte.
- set the checksum field to 0
- sum all the 16-bit words in the segment (header and data with the checksum field set to 0)
- take the 1st complement of this sum and wrap the overflow around

## Design Decisions Summary 🎨

### Using GBN instead of SR 📊

When resending segments after a timeout, the client uses a Go-Back-N policy. It sends all segments in the window.

This is as opposed to using a Selective Repeat, where the receiver individually acknowledges correctly received packets, so correctly received OOO packets will be buffered.

Pros of using GBN
- it simplifies receiver design a lot by removing receiver buffering altogether, so it the server only needs to know about `next_seq_num`. The code for this project was already super bulky so even though buffering OOO segments is the practical approach, I chose GBN for ease of implementation.
- Also means that the seq_nums of the TCPServer and the ack_nums of the TCPClient don’t have to be used! This made debugging a lot easier.

Cons of using GBN
- We throw away a correctly received packet, and a subsequent retransmission of that packet might be lost. This could cause more retransmissions.
- For large window sizes and large packet loss, GBN is not great. A single packet error can cause GBN to retransmit all the packets in the window (unnecessarily for a lot of the packets), so the file transfer can terminate before the entire file is received, since the client hits the retransmission limit. Or, the file transfer just takes a really really long time to complete.

### Retransmission timer adjustment ⏰

The timeout multiplier (what is multiplied to the `timeoutInterval` after a timeout) is set to 1.1 instead of the recommended doubling of the timeout.

Otherwise, the timeout increases too quickly and the file transfer will take a really long time (especially if there are a lot of retransmissions and the SampleRTTs aren’t also adjusting the timeout intervals).

### TIME_WAIT ⌚

After receiving a FIN, the server/client will wait for 5 seconds before terminating, which is a lot shorter than what the textbook says (30 seconds). This made it easier for testing.

## additional features
verbose logging and arg checking, which are boring to discuss. here's something more interesting.

### congestion control: fast retransmit 🚄

When window sizes get bigger and `newudpl` has a lot of packet loss, lots of duplicate ACKs are sent and it can take a while for packets to be retransmitted since the client has to wait for the timer to expire.

To try to detect packet losses earlier, I implemented a basic version of [fast retransmit](https://en.wikipedia.org/wiki/TCP_congestion_control). Upon receipt of 3 duplicate ACKs, we resend the first segment in the window, as it was probably lost.

The implementation is in `SimplexTCPClient.send_file_gbn()`:
    
```
# Part of fast Retransmit. If we receive 3 duplicate ACKs, then resend the segment
# with the lowest sequence number in the window.
if num_dup_acks == 3:
  logger.info(
    "Received 3 duplicate ACKs. Resending segment with seq_num {send_base}"
  )
  segment, num_retries = window[0]
  window[0] = (segment, 0)
  self.socket.sendto(segment, self.proxy_address)
  num_dup_acks = 0
```
    
# Testing Environment 🧪

This program works for my 2020 Mac (Intel) running Python 3.9.13, so it should work for Linux environments. I’m on macOS Big Sur v11.76.


