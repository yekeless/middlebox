
from scapy.all import sniff, IP, TCP
import time
import sys

# Fixed encoding parameters (mod 4 values)
ENCODING_PARAMS = [2, 3, 5, 7, 11, 13, 17, 19]  # mod 4 values (must be 0-3)
ENCODING_PARAMS = [val % 4 for val in ENCODING_PARAMS]
BITS_PER_PACKET = 7
NUMBER_OF_EXPERIMENTS = 100

received_binary_message = ""
end_flag = False
start_flag = True
start_time = 0
result_list = []


def decode_bits_from_seq_suffix(suffix, bits_per_packet, encoding_params):
    """
    Decodes bits of information from the sequence number suffix based on mod-4 and encoding_params.
    """
    binary = ""
    for i in range(bits_per_packet):
        two_bit_val = (suffix >> (2 * (bits_per_packet - 1 - i))) & 0b11
        expected_mod = encoding_params[i]
        if two_bit_val == expected_mod:
            binary += "1"
        else:
            binary += "0"
    return binary


def packet_handler(packet, bits_per_packet):
    """
    Handles incoming packets, decodes the binary message, and stops on '.' character.
    """
    global received_binary_message
    global start_flag
    global start_time
    global end_flag
    global result_list
    
    if start_flag:
        start_time = time.time()
        start_flag = False

    if IP in packet and TCP in packet and packet[TCP].dport == 8888:
        seq_num = packet[TCP].seq
        
        # Extract the bits used for encoding (bottom 2*bits_per_packet bits)
        mask = (1 << (2 * bits_per_packet)) - 1
        lower_bits = seq_num & mask
        
        binary_chunk = decode_bits_from_seq_suffix(
            lower_bits, 
            bits_per_packet, 
            ENCODING_PARAMS[:bits_per_packet]
        )
        
        received_binary_message += binary_chunk

        print(f"Received Seq: {seq_num}, Decoded Bits: {binary_chunk}")

        # Check for end marker '.' (binary: 00101110)
        if received_binary_message.endswith("00101110") and len(received_binary_message) % 8 == 0:
            end_flag = True
            print("End of message detected.")
            print(f"Final Binary Message: {received_binary_message}")
            print("Exiting...")
            end_time = time.time()
            result_list.append(end_time)
            print(f"Total time taken: {end_time - start_time} seconds")
            received_binary_message = ""


def scapy_tcp_receiver(bits_per_packet):
    """
    Listens for TCP packets on port 8888.
    """
    global end_flag
    global start_flag
    global result_list
    
    # Ensure bits_per_packet doesn't exceed available encoding parameters
    if bits_per_packet > len(ENCODING_PARAMS):
        print(f"Warning: bits_per_packet ({bits_per_packet}) exceeds available encoding parameters ({len(ENCODING_PARAMS)})")
        print(f"Using {len(ENCODING_PARAMS)} bits per packet instead")
        bits_per_packet = len(ENCODING_PARAMS)
    
    print(f"Listening for TCP packets on eth0...")
    print(f"Using {bits_per_packet} bits per packet")
    
    def custom_packet_handler(pkt):
        return packet_handler(pkt, bits_per_packet)
    
    for i in range(NUMBER_OF_EXPERIMENTS):
        while True:
            sniff(iface="eth0", filter="tcp port 8888", prn=custom_packet_handler, 
                 stop_filter=lambda x: end_flag, count=1)
            if end_flag:
                print(f"Experiment {i + 1} completed")
                end_flag = False
                start_flag = True 
                break

    print(result_list)


if __name__ == "__main__":
    scapy_tcp_receiver(BITS_PER_PACKET)