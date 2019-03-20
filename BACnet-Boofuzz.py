# VDA Labs BACnet Fuzzer
#!/usr/bin/env python
from boofuzz import *
import boofuzz.instrumentation
import os
import time

target_ip = "192.168.201.207"

def target_alive():
    response = os.system("ping -c 1 " + target_ip)
    if response == 0:
        return True
    else:
        return False

def reset_target():
    print "Stopping target\n"
    time.sleep(10)
    return True

def main():
    session = Session()
    target=Target(connection=SocketConnection(target_ip, 47808, proto='udp'))
    target.procmon = boofuzz.instrumentation.External(pre=None, post=target_alive, start=reset_target, stop=None)
    session.add_target(target)
    
    # start bacnet request packet
    s_initialize("bacnet_request_packet")
    if s_block_start("bacnet_virtual_link_control"):
        s_byte(0x81,name='type')
        s_byte(0x0a,name='function')
        s_word(0x1100,name='bvlc-length')
    s_block_end()
    if s_block_start("bacnet_npdu"):
        s_byte(0x01,name='version')
        s_byte(0x04,name='control')
    s_block_end()
    if s_block_start("bacnet_apdu")
        s_byte(0x00,name='apdu_type')
        s_byte(0x05,name='max_response_segments')
        s_byte(0x01,name='invoke_id')
        s_byte(0x0c,name='service_choice')
        s_byte(0x0c,name='context_tag1')
        s_dword(0xffff3f02,name='object_type')
        s_byte(0x19,name='context_tag')
        s_byte(0x79,name='property_identifier')
    s_block_end()
    # end bacnet request packet
 
    session.connect(s_get("bacnet_request_packet"))
    session.fuzz()

if __name__ == "__main__":
    main()
