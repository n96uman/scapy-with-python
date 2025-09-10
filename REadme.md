# 🛡️ My Scapy & Mini IDS Learning Journey

This repository is my **personal learning log** for Scapy and building simple IDS features. I write **what I learned, how it works, and what I tried**, step by step.

## **1. Packet Sniffing (First Steps)**

**What it is:**

* Packet sniffing is capturing **network traffic in real-time**. It’s like watching all the “letters” being sent and received on your network.

**How it works:**

* Scapy’s `sniff()` function listens on a network interface and captures packets.
* The `prn` argument lets you **call a function for each packet**.
* `packet.summary()` gives a **quick, readable summary** of the packet (source, destination, protocol, flags).
* **`store=0`**: do not keep packets in memory; useful for long-running sniffing.

**What I did / learned:**

* I captured 10 packets and printed their summaries.
* Learned that `sniff()` **does not send traffic**, it only observes packets from other apps or system processes.
* Realized how `prn` works and why it’s useful for real-time processing.


## **2 Saving and Analyzing Packets Later**

**What it is:**

* Sometimes we want to **capture network traffic now** and analyze it **later**, instead of processing packets in real-time.
* This is done using **PCAP files**, a standard format for storing captured network packets.

**How it works:**

* `wrpcap()` saves captured packets to a file.
* `rdpcap()` reads packets from a saved PCAP file for later analysis.
* This approach is useful for **testing, debugging, and building IDS features** without constantly running live captures.

**What I did / learned:**

* Captured network packets and saved them to a file.
* Learned how to reload the packets and analyze them later.
* Practiced filtering saved packets by protocol (TCP, UDP, DNS).
* Understood how **PCAP files bridge real-time capture and post-analysis**, which is important for IDS development.

**Example code: Save packets**

```python
from scapy.all import sniff, wrpcap

# Capture 10 packets
packets = sniff(count=10)

# Save to file
wrpcap("captured_packets.pcap", packets)
print("Packets saved to captured_packets.pcap")
```

**Example code: Read and analyze packets later**

```python
from scapy.all import rdpcap, TCP

# Read packets from file
packets = rdpcap("captured_packets.pcap")

# Analyze TCP packets
for pkt in packets:
    if TCP in pkt:
        print(f"TCP Packet: {pkt[IP].src} -> {pkt[IP].dst} on port {pkt[TCP].dport}")
```

## **3. Capturing by Protocol**

**What it is:**

* Capturing packets of a **specific type** (TCP, UDP, ICMP) instead of everything.

**How it works:**

* Using **BPF filters** in `sniff()`, like `filter="tcp"` or `filter="port 53`(for DNS).
* Or checking in Python: `if TCP in pkt:` for more flexibility.

**What I did / learned:**

* Captured only TCP packets and printed source/destination IPs.
* Learned the difference between **kernel-level filtering (BPF)** and **Python filtering**.
* Saw what kind of traffic appears when I browse, ping, or open apps.

Absolutely! I can create a **README-style note** for all the topics we discussed today, organized as **`t_topic1`**. Later, when you say **`t_day1`**, I can show you this note. Here’s a structured version you can add to your GitHub notes:


## **4️⃣ `defaultdict(list)`**

* Automatically initializes missing keys with an empty list.
* Example:

  ```python
  from collections import defaultdict
  scan_tracker = defaultdict(list)

  scan_tracker["192.168.1.10"].append(80)
  ```
* Perfect for **tracking ports per source IP** without manually checking keys.
* Can also use `defaultdict(int)` for counters or `defaultdict(set)` for unique items.

## **5️⃣ TCP Flags**

* **SYN flag** = `"S"` in Scapy.
* Other common flags:

| Flag | Meaning                 |
| ---- | ----------------------- |
| S    | SYN (start connection)  |
| A    | ACK (acknowledgment)    |
| F    | FIN (finish connection) |
| R    | RST (reset connection)  |
| P    | PSH (push data)         |
| U    | URG (urgent)            |

* SYN-ACK = `"SA"`
* Use `"S"` to detect **port scan attempts**.

## **6️⃣ `haslayer()`**

* Checks if a packet contains a specific layer.
* Example:

  ```python
  if pkt.haslayer(TCP):
      print(pkt[TCP].dport)
  ```
* Ensures **your code doesn’t crash** when a layer is missing.
* Can also use `if TCP in pkt:` (similar behavior).

## **7️⃣ Port Scan Detection Logic**

* **Store attempts with timestamp and port:**

  ```python
  scan_tracker[src].append((now, dport))
  ```
* **Filter only recent attempts:**

  ```python
  scan_tracker[src] = [(t, p) for (t, p) in scan_tracker[src] if now - t <= TIME_WINDOW]
  ```
* **Get unique ports in the window:**

- {} save only uniq ports.

  ```python
  unique_ports = {p for (t, p) in scan_tracker[src]}
  ```
* **Detect scan:** If number of unique ports > threshold → alert.

**Explanation:**

* Each `src` IP maps to a **list of `(timestamp, port)` tuples**.
* Filtering keeps only packets in the **time window**.
* Using a **set** extracts **unique destination ports** to identify fast scanning behavior.

## **8  IP Layer**

* Contains **network addresses** (source and destination).
* Access using `pkt[IP]`.

**Common fields:**

| Field | Meaning                | Example       |
| ----- | ---------------------- | ------------- |
| `src` | Source IP address      | `pkt[IP].src` |
| `dst` | Destination IP address | `pkt[IP].dst` |
| `ttl` | Time to Live           | `pkt[IP].ttl` |

**Example:**

```python
src_ip = pkt[IP].src
dst_ip = pkt[IP].dst
print(f"{src_ip} -> {dst_ip}")
```

---

## **9 TCP Layer**

* Contains **transport layer info** (ports, flags, sequence numbers).
* Access using `pkt[TCP]`.

**Common fields:**

| Field   | Meaning                    | Example          |
| ------- | -------------------------- | ---------------- |
| `sport` | Source port                | `pkt[TCP].sport` |
| `dport` | Destination port           | `pkt[TCP].dport` |
| `flags` | TCP flags (SYN, ACK, etc.) | `pkt[TCP].flags` |
| `seq`   | Sequence number            | `pkt[TCP].seq`   |
| `ack`   | Acknowledgment number      | `pkt[TCP].ack`   |

**Example:**

```python
dst_port = pkt[TCP].dport
flags = pkt[TCP].flags
print(f"Port {dst_port}, Flags: {flags}")
```

---

## **10 Why layer matters**

* **IP addresses** are **network layer**, not TCP.
* **Ports and flags** are **transport layer**, not IP.
* Accessing a field from the wrong layer will **cause errors**.


## **11 Quick Reference Table**

| Field            | Layer | Scapy Example    |
| ---------------- | ----- | ---------------- |
| Source IP        | IP    | `pkt[IP].src`    |
| Destination IP   | IP    | `pkt[IP].dst`    |
| Source Port      | TCP   | `pkt[TCP].sport` |
| Destination Port | TCP   | `pkt[TCP].dport` |
| TCP Flags        | TCP   | `pkt[TCP].flags` |
