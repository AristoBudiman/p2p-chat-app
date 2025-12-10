import streamlit as st
import socket
import time
from datetime import datetime

from nacl.public import PrivateKey, PublicKey, Box
from cryptography.fernet import Fernet
import hashlib
import base64

import threading
from streamlit.runtime.scriptrunner import add_script_run_ctx

st.set_page_config(page_title="P2P Chat App", layout="centered")

if 'initialized' not in st.session_state:
    st.session_state.initialized = True
    st.session_state.server_sock = None 
    st.session_state.sock = None 
    st.session_state.role = None
    st.session_state.is_hosting = False
    st.session_state.connected = False
    st.session_state.messages = []
    
    my_key = PrivateKey.generate()
    st.session_state.my_priv = my_key
    st.session_state.my_pub = my_key.public_key
    st.session_state.partner_pub = None
    st.session_state.session_key = None

    st.session_state.my_confirmation = False
    st.session_state.partner_confirmation = False

def get_fingerprint(public_key_bytes):
    full_hash = hashlib.sha256(public_key_bytes).hexdigest()
    short = full_hash[:16].upper()
    return '-'.join([short[i:i+4] for i in range(0, len(short), 4)])

def create_session_key(partner_pub_key):
    box = Box(st.session_state.my_priv, partner_pub_key)
    shared_secret_bytes = box.shared_key()
    aes_key_b64 = base64.urlsafe_b64encode(shared_secret_bytes)
    return Fernet(aes_key_b64)

def send_verification_signal():
    try:
        signal = "SYS::VERIFIED"
        encrypted_msg = st.session_state.session_key.encrypt(signal.encode('utf-8'))
        st.session_state.sock.send(encrypted_msg)
        st.session_state.my_confirmation = True
    except Exception as e:
        st.error(f"Gagal kirim verifikasi: {e}")

def handshake(connection, is_host):
    time.sleep(0.5)
    try:
        my_pub_bytes = bytes(st.session_state.my_pub)
        if is_host:
            connection.send(my_pub_bytes)
            partner_pub_bytes = connection.recv(32)
        else:
            partner_pub_bytes = connection.recv(32)
            connection.send(my_pub_bytes)
            
        if not partner_pub_bytes or len(partner_pub_bytes) != 32:
            st.error("Invalid Key")
            return

        st.session_state.partner_pub = PublicKey(partner_pub_bytes)
        st.session_state.session_key = create_session_key(st.session_state.partner_pub)
        st.session_state.connected = True
        
        st.session_state.my_confirmation = False
        st.session_state.partner_confirmation = False
        
        recv_thread = threading.Thread(target=receive_messages, daemon=True)
        add_script_run_ctx(recv_thread)
        recv_thread.start()
        
    except Exception as e:
        st.error(f"Handshake Error: {e}")
        reset_connection()

def start_chat(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", int(port))) 
        server.listen(1)
        st.session_state.server_sock = server
        
        def accept_partner():
            try:
                client, addr = server.accept()
                st.session_state.sock = client
                st.session_state.role = "Host"
                st.session_state.is_hosting = True
                handshake(client, is_host=True)
            except Exception as e:
                print(f"Error accept: {e}")

        accept_thread = threading.Thread(target=accept_partner, daemon=True)
        add_script_run_ctx(accept_thread)
        accept_thread.start()
        return True
    except Exception as e:
        st.error(f"Gagal start chat: {e}")
        return False

def join_chat(target_ip, target_port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_ip, int(target_port)))
        st.session_state.sock = client
        st.session_state.role = "Partner"
        handshake(client, is_host=False)
        return True
    except Exception as e:
        st.error(f"Gagal terhubung: {e}")
        return False

def send_message():
    user_input = st.session_state.chat_input
    if user_input and st.session_state.connected:
        try:
            encrypted_msg = st.session_state.session_key.encrypt(user_input.encode('utf-8'))
            st.session_state.sock.send(encrypted_msg)
            timestamp = datetime.now().strftime("%H:%M")
            st.session_state.messages.append({"sender": "Me", "text": user_input, "time": timestamp})
        except Exception as e:
            st.error(f"Gagal mengirim pesan: {e}")

def receive_messages():
    sock = st.session_state.sock
    while st.session_state.connected:
        try:
            encrypted_msg = sock.recv(4096)
            if not encrypted_msg: 
                break
            
            try:
                decrypted_text = st.session_state.session_key.decrypt(encrypted_msg).decode('utf-8')
                if decrypted_text == "SYS::VERIFIED":
                    st.session_state.partner_confirmation = True
                    st.rerun()
                    continue
                
                timestamp = datetime.now().strftime("%H:%M")
                st.session_state.messages.append({
                    "sender": "Partner",
                    "text": decrypted_text,
                    "time": timestamp
                })
            except: pass 
        except: break
    
    reset_connection()
    st.rerun()

def reset_connection():
    if st.session_state.get('sock'):
        try: st.session_state.sock.close()
        except: pass
    if st.session_state.get('server_sock'):
        try: st.session_state.server_sock.close()
        except: pass
    st.session_state.connected = False
    st.session_state.role = None
    st.session_state.is_hosting = False
    st.session_state.messages = []
    st.session_state.my_confirmation = False
    st.session_state.partner_confirmation = False

if not st.session_state.connected:
    st.title("P2P Chat App")
    col1, col2 = st.columns(2)
    with col1:
        st.header("1. Hosting Room")
        host_port = st.text_input("Port Listen", value="5001")
        if not st.session_state.is_hosting:
            if st.button("Start Server", type="primary"):
                if start_chat(host_port):
                    st.session_state.is_hosting = True
                    st.rerun()
        else:
            st.info(f"Menunggu koneksi di Port {host_port}...")
            if st.button("Cancel"):
                reset_connection()
                st.rerun()
            time.sleep(1)
            st.rerun()
    with col2:
        st.header("2. Join Room")
        target_ip = st.text_input("IP Host", placeholder="127.0.0.1")
        target_port = st.text_input("Port Host", value="5001")
        if st.button("Connect"):
            if join_chat(target_ip, target_port):
                st.rerun()

else:
    is_locked = not (st.session_state.my_confirmation and st.session_state.partner_confirmation)
    
    if is_locked:
        st.warning("CHAT TERKUNCI - Verifikasi Partner diperlukan")
    else:
        st.success("CHAT TERBUKA - Partner Terverifikasi")

    with st.expander("Verifikasi Fingerprint", expanded=is_locked):
        col_fp1, col_fp2 = st.columns(2)
        my_fp = get_fingerprint(bytes(st.session_state.my_pub))
        partner_fp = get_fingerprint(bytes(st.session_state.partner_pub))

        with col_fp1:
            st.caption("Fingerprint SAYA")
            st.code(my_fp)
            if st.session_state.partner_confirmation:
                st.success("Partner sudah konfirmasi")
            else:
                st.warning("Menunggu partner konfirmasi ...")

        with col_fp2:
            st.caption("Fingerprint PARTNER")
            st.code(partner_fp)
            if not st.session_state.my_confirmation:
                if st.button("Konfirmasi Benar", type="primary"):
                    send_verification_signal()
                    st.rerun()
            else:
                st.info("Anda sudah konfirmasi")

        if is_locked:
            st.caption("Hubungi teman Anda, cocokkan fingerprint. Jika sama, klik Konfirmasi.")
    
    if st.button("Disconnect"):
        reset_connection()
        st.rerun()

    st.divider()

    chat_container = st.container(height=350)
    with chat_container:
        for msg in st.session_state.messages:
            is_me = msg['sender'] == "Me"
            chat_role = "user" if is_me else "assistant"
            
            with st.chat_message(chat_role):
                if is_me:
                    st.markdown("**Me**")
                else:
                    st.markdown("**Partner**")

                st.write(msg['text'])
                st.caption(f"{msg['time']}")

    placeholder_text = "Verifikasi Partner diperlukan ..." if is_locked else "Ketik pesan ..."
    
    if st.chat_input(placeholder_text, key="chat_input", disabled=is_locked, on_submit=send_message):
        pass

    time.sleep(1)
    st.rerun()