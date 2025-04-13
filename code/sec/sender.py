
import os
import time
import string
import random
import sys
from scapy.all import Ether, IP, TCP, Raw, sendp

# Fixed encoding parameters (mod 4 values)
ENCODING_PARAMS = [2, 3, 5, 7, 11, 13, 17, 19]  # mod 4 values (must be 0-3)
ENCODING_PARAMS = [val % 4 for val in ENCODING_PARAMS]
BITS_PER_PACKET = 7
STARTING_SEQ = 10
STEP_SIZE = 1
NUMBER_OF_EXPERIMENTS = 100

def convert_string_message_to_binary(message):
    """
    Converts the incoming string value to binary format.
    """
    binary_message_to_transfer = ''.join(format(i, '08b') for i in bytearray(message, encoding='utf-8'))
    return binary_message_to_transfer

def generate_random_message(min_length=5, max_length=10):
    """
    Creates a random string, e.g., for the payload of the packet.
    """
    assert 0 < min_length, "min_length must be bigger than 0"
    assert min_length <= max_length, "min_length must be smaller than or equal to the max_length"
    letters_digits = string.ascii_letters + string.digits
    punctuation = ',?!'
    all_chars = " " * 50 + letters_digits * 5 + punctuation
    length = random.randint(min_length - 1, max_length - 1)
    random_string = ''.join(random.choice(all_chars) for _ in range(length))
    random_string += "."
    return random_string

def generate_random_binary_message(min_length=50, max_length=100):
    """
    Generates a random string whose length is between the min_length and max_length,
    and converts it to binary format.
    """
    random_message = generate_random_message(min_length=min_length, max_length=max_length)
    random_binary_message = convert_string_message_to_binary(message=random_message)
    return random_binary_message


def encode_bits_to_seq_suffix(bit_window, encoding_params):
    """
    Encodes N bits into sequence number suffix using the first N values from encoding_params.
    If bit is 1 → use a value where (val % 4 == target).
    If bit is 0 → randomly pick one where (val % 4 != target).
    """
    bits_per_packet = len(bit_window)
    suffix = 0
    for i in range(bits_per_packet):
        target_mod = encoding_params[i]
        if bit_window[i] == '1':
            matching_vals = [v for v in range(4) if v % 4 == target_mod]
        else:
            matching_vals = [v for v in range(4) if v % 4 != target_mod]

        selected_val = random.choice(matching_vals)
        suffix |= (selected_val << (2 * (bits_per_packet - 1 - i)))  # insert 2 bits in the correct position
    
    return suffix


def generate_full_tcp_seq_number(packet_index, step_size, start_seq, bit_window, encoding_params):
    bits_per_packet = len(bit_window)
    # Create the upper bits by shifting values to the left
    # Leave enough space in the lower bits for encoding (2 bits per covert bit)
    shift_amount = 2 * bits_per_packet
    upper_bits = ((start_seq + packet_index * step_size) << shift_amount) & (0xFFFFFFFF << shift_amount)
    
    # Covert part (lower bits): from encoding
    lower_bits = encode_bits_to_seq_suffix(bit_window, encoding_params[:bits_per_packet])
    
    # Combine into full 32-bit sequence number
    full_seq = upper_bits | (lower_bits & (2**(2*bits_per_packet) - 1))
    return full_seq


def scapy_tcp_sender(bits_per_packet):
    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    message = generate_random_message(1, 5)
    
    # Generate a binary message
    binary_message = generate_random_binary_message(min_length=7, max_length=7)
    
    if not host:
        print("INSECURENET_HOST_IP environment variable is not set.")
        return

    try:
        start = time.time()
        iteration = 0
        
        print(f"Using {bits_per_packet} bits per packet")
        print(f"Sending binary message: {binary_message}")

        while iteration < len(binary_message):
            # Get the next chunk of bits to send (up to bits_per_packet)
            window = binary_message[iteration:iteration + bits_per_packet]
            
            # If we don't have enough bits to fill a complete window, pad with zeros
            if len(window) < bits_per_packet:
                window = window.ljust(bits_per_packet, '0')
            
            # Generate the sequence number with our encoded bits
            custom_seq = generate_full_tcp_seq_number(
                (iteration // bits_per_packet), 
                STEP_SIZE, 
                STARTING_SEQ, 
                window, 
                ENCODING_PARAMS
            )
            
            # Craft a full Ethernet + IP + TCP packet
            ether = Ether()
            ip = IP(dst=host)
            tcp = TCP(dport=port, seq=custom_seq)
            packet = ether / ip / tcp / message

            # Send the packet
            sendp(packet, iface="eth0", verbose=False)
            print(f"Sent: {packet.summary()} with sequence number: {custom_seq}")
            print(f"Encoded bits: {window}")
            
            iteration += bits_per_packet
            
            time.sleep(0.1)
            
        end = time.time()
        print(f"Total time taken: {end - start} seconds")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    result_list = []
    for i in range(NUMBER_OF_EXPERIMENTS):
        begin = time.time()
        scapy_tcp_sender(BITS_PER_PACKET)
        end = time.time()
        result_list.append(begin)
        print(f"Experiment {i + 1} took {end - begin} seconds")
        time.sleep(1)
    print(result_list)