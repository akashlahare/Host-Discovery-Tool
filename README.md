# 🛰️ Host Discovery Tool

A **Python-based multithreaded ping scanner** that scans a range of IP addresses using ICMP echo requests. It identifies reachable hosts, displays their response times, and allows custom IP range input for flexible network discovery.

---

## 🚀 Key Features

- **Multithreading** – Speeds up scanning by pinging multiple hosts in parallel.
- **Custom IP Range** – Input any start and end IPv4 addresses to define the scan range.
- **Response Time Display** – Shows the time taken to respond for each reachable host.
- **Cross-platform Compatible** – Works on both Windows and Linux.

---

## 📸 Screenshot

![Host Discovery Tool](https://github.com/akashlahare/Ping-Scanner-Tool/blob/main/Ping%20Scanner.png?raw=true)

---

## 🛠️ How It Works

The tool uses Python’s `subprocess`, `threading`, and `ipaddress` modules to:
- Convert the IP range into numeric values
- Spawn a thread for each IP
- Ping each IP once
- Record the response time and output status (reachable/unreachable)

---

## 👨‍💻 Author : Akash Lahare

### 🔗 [LinkedIn](https://www.linkedin.com/in/akashlahare/)  
### 📂 [More Projects](https://github.com/akashlahare)
---

## 📄 License
 🔗 [MIT License](https://choosealicense.com/licenses/mit/)
