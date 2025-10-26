import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct

# ==============================
# Helper Classes & Functions
# ==============================

class SimpleReplayWindow:
    """Simple replay protection: keeps highest sequence number seen."""
    def __init__(self):
        self.highest = 0

    def check_and_update(self, seq):
        if seq > self.highest:
            self.highest = seq
            return True
        return False


def build_mock_ipv4_packet(payload: bytes) -> bytes:
    """Simulate an IP packet: 20-byte header + payload"""
    version_ihl = (4 << 4) | 5
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            version_ihl, 0, 20 + len(payload), 0, 0, 64, 0, 0,
                            b'\x0A\x00\x00\x01', b'\x0A\x00\x00\x02')
    return ip_header + payload


def esp_encrypt_transport(ip_pkt, key, spi, seq):
    """Encrypts IP payload using AES-GCM (ESP Transport Mode)"""
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    spi_bytes = struct.pack("!I", spi)
    seq_bytes = struct.pack("!I", seq)
    ciphertext = aesgcm.encrypt(iv, ip_pkt[20:], ip_pkt[:20] + spi_bytes + seq_bytes)
    return ip_pkt[:20] + spi_bytes + seq_bytes + iv + ciphertext, iv, ciphertext


def esp_decrypt_transport(esp_pkt, key, replay_window):
    """Decrypts ESP packet and checks replay protection"""
    ip_header = esp_pkt[:20]
    spi = struct.unpack("!I", esp_pkt[20:24])[0]
    seq = struct.unpack("!I", esp_pkt[24:28])[0]
    iv = esp_pkt[28:40]
    ciphertext = esp_pkt[40:]

    if not replay_window.check_and_update(seq):
        raise ValueError(f"Replay detected or sequence number not acceptable: {seq}")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, ip_header + struct.pack("!I", spi) + struct.pack("!I", seq))
    return ip_header + plaintext, spi, seq


def split_payload(payload: bytes, n_parts: int) -> list:
    """Split payload bytes into n_parts as evenly as possible."""
    if n_parts <= 1:
        return [payload]
    total = len(payload)
    if total == 0:
        return [b''] * n_parts
    base = total // n_parts
    remainder = total % n_parts
    parts, idx = [], 0
    for i in range(n_parts):
        size = base + (1 if i < remainder else 0)
        parts.append(payload[idx: idx + size])
        idx += size
    return parts


# ==============================
# Streamlit UI
# ==============================

st.set_page_config(page_title="ESP Transport Mode Simulator", page_icon="🔒", layout="wide")

# ======= Custom CSS =======
st.markdown("""
<style>
.stApp {background: linear-gradient(135deg, #000000, #001a33, #002b80, #0040ff); color: #e6e6e6;}
h1, h2, h3, h4 {color: #4da6ff !important; font-weight: 700; text-shadow: 0px 0px 10px rgba(77,166,255,0.6);}
.streamlit-expanderHeader {background-color: rgba(0, 51, 102, 0.8) !important; color: #ffffff !important; font-weight: 600; border-radius: 10px; padding: 6px 10px;}
.streamlit-expanderContent {background-color: rgba(0, 0, 0, 0.55) !important; padding: 10px; border-radius: 10px; color: #d9e6ff !important;}
div.stButton > button {background: linear-gradient(90deg, #0033cc, #0040ff); color: white; border-radius: 10px; padding: 0.6em 1.2em; font-size: 1em; font-weight: 600; border: none; box-shadow: 0px 0px 12px rgba(0,0,0,0.4); transition: 0.3s;}
div.stButton > button:hover {background: linear-gradient(90deg, #3399ff, #0073e6); transform: scale(1.05);}
pre, code {background-color: rgba(0, 0, 0, 0.7) !important; color: #99ccff !important; border-radius: 8px; padding: 8px; font-size: 0.9em;}
hr { border: 1px solid #0077ff; opacity: 0.5; }
.block-container {background-color: rgba(0,0,0,0.4); padding: 2rem; border-radius: 15px;}
/* Sidebar Transparent */
.css-1d391kg {background-color: rgba(0,0,0,0) !important;}
.css-18e3th9 {background-color: rgba(0,0,0,0) !important;}
</style>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("📚 ESP Simulator")
page = st.sidebar.radio("Navigate:", ["📘 Theory", "🎯 Objectives", "🧩 Procedure", "⚙️ Simulation", "💻 Code"])

# ==============================
# Pages
# ==============================

# Add common title on top of every page
st.title("🔒 Encapsulating Security Payload (ESP) - Transport Mode Simulation")

# --------------------------
# Theory
# --------------------------
if page == "📘 Theory":
    st.markdown("""
**Encapsulating Security Payload (ESP)** is a core component of **IPsec**, providing **confidentiality, integrity, and authentication** for IP packets.

In **Transport Mode**, only the **payload** of the IP packet is encrypted, leaving the header visible to allow routing.  
ESP adds **SPI, Sequence Number, IV, and Authentication Tag** to secure the payload.

AES-GCM is used for encryption as it combines encryption and authentication efficiently.  
Replay protection is achieved through sequence numbers to prevent duplicate or old packets.  

#### Packet Structure (ESP Transport Mode)

| Field | Description |
|-------|-------------|
| SPI | Security Parameter Index identifies the security association |
| Sequence Number | Prevents replay attacks by tracking order |
| IV | Initialization Vector ensures unique encryption per packet |
| Payload Data | Encrypted user data |
| Authentication Tag | Guarantees integrity and authenticity |

**Summary:** ESP ensures that even if packets are intercepted, the payload remains unreadable and untampered.
""")

# --------------------------
# Objectives
# --------------------------
elif page == "🎯 Objectives":
    st.markdown("""
                


The main objectives of this simulation are to provide a practical understanding of **ESP Transport Mode** and its security mechanisms.  

                
1. Demonstrate AES-GCM encryption & decryption for IP payloads.  
                

                

2. Implement replay protection using sequence numbers.  
                

3. Visualize payload fragmentation and reassembly.  
                

4. Enable users to input payloads, fragment them, encrypt, and decrypt.  
                

5. Understand how SPI, IV, Sequence Number, and Authentication Tag work in practice.  


""")

# --------------------------
# Procedure
# --------------------------
elif page == "🧩 Procedure":
    st.markdown("""
The simulation follows a **stepwise approach** to demonstrate ESP Transport Mode:

1. **Create Mock IPv4 Packet** – A 20-byte header is added to user-provided payload to simulate a real IP packet.  
2. **Fragment Payload** – If payload is large, split into smaller fragments.  
3. **Encrypt Each Fragment** – Use AES-GCM to encrypt payload and generate authentication tag.  
4. **Attach ESP Headers** – Add SPI, Sequence Number, IV to each fragment.  
5. **Transmit Fragments** – Simulate sending over network.  
6. **Decrypt Fragments** – Receiver decrypts each fragment using AES-GCM.  
7. **Check Replay Protection** – Sequence numbers are verified to reject duplicates.  
8. **Reassemble Payload** – Combine all decrypted fragments to reconstruct the original payload.  
9. **Verify Integrity** – Confirm that the reassembled payload matches the original input.

**Step Representation Table**

| Step | Description |
|------|------------|
| 1 | Mock IP packet generation |
| 2 | Fragment payload |
| 3 | AES-GCM encryption |
| 4 | Add ESP headers (SPI, Seq, IV) |
| 5 | Transmit |
| 6 | Decrypt |
| 7 | Replay protection check |
| 8 | Reassembly |
| 9 | Verify payload integrity |
""")

# --------------------------
elif page == "💻 Code":
    st.title("💻 Complete Code")

    st.markdown("Below is the **full code** used in the simulation including **all functions**.")

    st.subheader("1️⃣ SimpleReplayWindow Class")
    st.code("""
class SimpleReplayWindow:
    def __init__(self):
        self.highest = 0
    def check_and_update(self, seq):
        if seq > self.highest:
            self.highest = seq
            return True
        return False
""", language="python")

    st.subheader("2️⃣ Mock IPv4 Packet")
    st.code("""
def build_mock_ipv4_packet(payload: bytes) -> bytes:
    version_ihl = (4 << 4) | 5
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            version_ihl, 0, 20 + len(payload), 0, 0, 64, 0, 0,
                            b'\\x0A\\x00\\x00\\x01', b'\\x0A\\x00\\x00\\x02')
    return ip_header + payload
""", language="python")

    st.subheader("3️⃣ Encryption Function")
    st.code("""
def esp_encrypt_transport(ip_pkt, key, spi, seq):
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    spi_bytes = struct.pack("!I", spi)
    seq_bytes = struct.pack("!I", seq)
    ciphertext = aesgcm.encrypt(iv, ip_pkt[20:], ip_pkt[:20] + spi_bytes + seq_bytes)
    return ip_pkt[:20] + spi_bytes + seq_bytes + iv + ciphertext, iv, ciphertext
""", language="python")

    st.subheader("4️⃣ Decryption Function")
    st.code("""
def esp_decrypt_transport(esp_pkt, key, replay_window):
    ip_header = esp_pkt[:20]
    spi = struct.unpack("!I", esp_pkt[20:24])[0]
    seq = struct.unpack("!I", esp_pkt[24:28])[0]
    iv = esp_pkt[28:40]
    ciphertext = esp_pkt[40:]

    if not replay_window.check_and_update(seq):
        raise ValueError(f"Replay detected: {seq}")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, ip_header + struct.pack("!I", spi) + struct.pack("!I", seq))
    return ip_header + plaintext, spi, seq
""", language="python")

    st.subheader("5️⃣ Payload Fragmentation")
    st.code("""
def split_payload(payload: bytes, n_parts: int) -> list:
    if n_parts <= 1:
        return [payload]
    total = len(payload)
    base = total // n_parts
    remainder = total % n_parts
    parts, idx = [], 0
    for i in range(n_parts):
        size = base + (1 if i < remainder else 0)
        parts.append(payload[idx: idx + size])
        idx += size
    return parts
""", language="python")

# --------------------------
# --------------------------
# Simulation
# --------------------------
elif page == "⚙️ Simulation":
    col1, col2, col3 = st.columns(3)
    spi_input = col1.text_input("SPI (hex):", "0x1001")
    total_packets = col2.number_input("Number of fragments:", 1, 10, 1)
    payload_input = col3.text_area("Payload text:", "Hello ESP Transport Mode!")

    if st.button("🔐 Encrypt & Decrypt"):
        try:
            spi = int(spi_input, 16) if spi_input.startswith("0x") else int(spi_input)
        except:
            spi = 0x1001

        key = AESGCM.generate_key(bit_length=128)
        st.info(f"AES Key: `{key.hex()}`")

        full_payload_bytes = payload_input.encode()
        fragments = split_payload(full_payload_bytes, int(total_packets))
        st.markdown(f"Payload length {len(full_payload_bytes)} bytes → {len(fragments)} fragment(s).")

        replay = SimpleReplayWindow()
        recovered_fragments = {}

        for i, frag in enumerate(fragments):
            seq_num = i + 1
            st.subheader(f"Fragment {seq_num}")
            ip_pkt = build_mock_ipv4_packet(frag)
            esp_pkt, iv, ciphertext = esp_encrypt_transport(ip_pkt, key, spi, seq_num)

            col_enc, col_dec = st.columns(2)
            with col_enc:
                st.markdown("#### 🔒 Encrypted Fragment")
                st.code(f"SPI: {hex(spi)}\\nSeq: {seq_num}\\nIV: {iv.hex()}\\nCiphertext: {ciphertext.hex()}", language="bash")
            with col_dec:
                st.markdown("#### 🔓 Decryption & Replay Check")
                try:
                    recovered, used_spi, used_seq = esp_decrypt_transport(esp_pkt, key, replay)
                    recovered_fragments[used_seq] = recovered[20:]
                    st.success(f"Recovered: `{recovered[20:].decode(errors='ignore')}`")
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
                try:
                    _ = esp_decrypt_transport(esp_pkt, key, replay)
                except Exception as e:
                    st.info(f"Replay rejected: {e}")

        st.markdown("---")
        st.subheader("📥 Reassembly")
        reassembled = b''.join([recovered_fragments.get(i+1, b'') for i in range(len(fragments))])
        if len(reassembled) != len(full_payload_bytes):
            st.error("Some fragments missing!")
        else:
            st.success("All fragments reassembled successfully ✅")
            st.write("**Reassembled Payload:**", reassembled.decode(errors='ignore'))
