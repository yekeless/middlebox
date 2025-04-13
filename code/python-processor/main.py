import asyncio
from nats.aio.client import Client as NATS
import os, random
from scapy.all import Ether, IP, TCP

async def run():
    nc = NATS()

    nats_url = os.getenv("NATS_SURVEYOR_SERVERS", "nats://nats:4222")
    await nc.connect(nats_url)

    async def message_handler(msg):
        subject = msg.subject
        data = msg.data  # This is the raw packet data
        print(f"Received message on '{subject}'")
        
        try:
            # Parse the raw bytes as an Ethernet frame
            packet = Ether(data)  # Scapy Ether layer parsing
            print(f"Parsed Packet:\n{packet.show()}")  # Display the parsed packet

            # Add random delay
            delay = random.expovariate(1 / 10e-3)
            await asyncio.sleep(delay)
            print(f"Applied delay: {delay}s")
            
            # Check if the packet contains IP and TCP layers
            if IP in packet and TCP in packet:
                if subject == "inpktsec":
                    # Modify the packet if necessary
                    # For example, change the source IP or port, etc.
                    print(f"Packet from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")
                    
                    # Publish the modified packet to the next topic
                    await nc.publish("outpktinsec", bytes(packet))  # Send packet to outpktinsec

                elif subject == "inpktinsec":
                    # Similarly handle the inpktinsec messages
                    print(f"Packet from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")
                    
                    # Publish the modified packet to the next topic
                    await nc.publish("outpktsec", bytes(packet))  # Send packet to outpktsec

        except Exception as e:
            print(f"Error parsing packet: {e}")

    # Subscribe to inpktsec and inpktinsec topics
    await nc.subscribe("inpktsec", cb=message_handler)
    await nc.subscribe("inpktinsec", cb=message_handler)
    print("Subscribed to inpktsec and inpktinsec topics")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Disconnecting...")
        await nc.close()

if __name__ == '__main__':
    asyncio.run(run())
