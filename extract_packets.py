"""
    This code about extracting packets' details from file and assign them
    to object of Packet class
"""
import re
from typing import List

SEARCH_PATTERN = (
                'src=(?P<src>[\w:]*) [\S]* dst=(?P<dst>[\w:]*) [\S]* '
                'type=(?P<type>[\w]*) [\S]* length=(?P<length>[\w]*) '
                '[\S]* nb_segs=(?P<nb_segs>[\w]*) [\S]* '
                'RSS hash=(?P<rss_hash>[\w]*) [\S]* '
                'RSS queue=(?P<rss_queue>[\w]*) [[\S]* '
                'hw ptype: (?P<hw_ptype>[\w ]*)]* [[\S]* '
                'sw ptype: (?P<sw_ptype>[\w ]*) [\S]*]*[ \- ]* '
                'l2_len=(?P<l2_len>[\w]*)([ \- ]* '
                'inner_l2_len=(?P<inner_l2_len>[\w]*))*([ \- ]* '
                'l3_len=(?P<l3_len>[\w]*))*([ \- ]* '
                'inner_l3_len=(?P<inner_l3_len>[\w]*))*([ \- ]* '
                'l4_len=(?P<l4_len>[\w]*))*[ \- ]*'
                'Receive queue=(?P<receive_queue>[\w]*)[[\n ]*'
                'ol_flags: (?P<ol_flags>[\w ]*)]*'
                )


class Packet:
    """This class is about holding the information of the packets
    Attributes
    -------
    src : str
        the source of the packet.
    dst : str
        the destination of the packet.
    packet_type : str
        the type of the packet
    length : int
        the length of the packet
    nb_segs : int
        the number of the segments
    rss_hash : int
    rss_queue : int
    hw_ptype : List
    sw_ptype : List
    l2_len : int
    inner_l2_len : int
    l3_len : int
    inner_l3_len : int
    l4_len : int
    receive_queue : int
    ol_flags : List
    """
    def __init__(self, src: str = None, dst: str = None,
                 packet_type: int = None, length: int = None,
                 nb_segs: int = None, rss_hash: int = None,
                 rss_queue: int = None, hw_ptype: List = None,
                 sw_ptype: List = None, l2_len: int = None,
                 inner_l2_len: int = None, l3_len: int = None,
                 inner_l3_len: int = None, l4_len: int = None,
                 receive_queue: int = None, ol_flags: List = None
                 ):
        self.src = src
        self.dst = dst
        self.packet_type = packet_type
        self.length = length
        self.nb_segs = nb_segs
        self.rss_hash = rss_hash
        self.rss_queue = rss_queue
        self.hw_ptype = hw_ptype
        self.sw_ptype = sw_ptype
        self.l2_len = l2_len
        self.inner_l2_len = inner_l2_len
        self.l3_len = l3_len
        self.inner_l3_len = inner_l3_len
        self.l4_len = l4_len
        self.receive_queue = receive_queue
        self.ol_flags = ol_flags


def open_file(filename: str) -> str:
    """open packets file and get the contents of the file

    Parameters
    -------
    filename : str
        is the name of the file that is going to be opened
        and processed

    Returns
    -------
    str
        the contents of the opened file
    """
    with open(filename, encoding="utf-8") as packets_file:
        return packets_file.read()  # Get the contents of the file


def get_packets_info(file_content: str, search_pattern: str) -> List:
    """get and assign the info of the packets from the list

    Parameters
    -------
    file_content: str
         contains the contents of the file which holds the details of
         the packets

    search_pattern: str
        pattern used to extract the details of each packet

    Returns
    -------
    List
        the packets objects which contain the details of each packet
    """
    packets_list = []
    packets = re.finditer(search_pattern, file_content)
    for packet in packets:
        if packet is not None:
            packet_h = Packet(
             src=packet.group('src'),
             dst=packet.group('dst'),
             packet_type=packet.group('type'),
             length=packet.group('length'),
             nb_segs=packet.group('nb_segs'),
             rss_hash=packet.group('rss_hash'),
             rss_queue=packet.group('rss_queue'),
             hw_ptype=packet.group('hw_ptype').split(' '),
             sw_ptype=packet.group('sw_ptype').split(' '),
             l2_len=packet.group('l2_len'),
             inner_l2_len=packet.group('inner_l2_len'),
             l3_len=packet.group('l3_len'),
             inner_l3_len=packet.group('inner_l3_len'),
             l4_len=packet.group('l4_len'),
             receive_queue=packet.group('receive_queue'),
             ol_flags=packet.group('ol_flags').split(' '))

            # append the packet into the list
            packets_list.append(packet_h)
        else:
            print("No packet to analyze")
    return packets_list


def print_packets_info(packets: List) -> None:
    """To print the details of the processed packets based on the object of each packet
        printing the data in formatted way
    Parameters
    -------
    packets: List
        list to be logged in order to ensure that the regex working properly

    Returns
    -------
    None
    """
    for packet in packets:
        print(f"""
        Src : {packet.src}, Dst : {packet.dst}
        Type : {packet.packet_type}, Length : {packet.length}
        nb_segs : {packet.nb_segs}, RSS hash : {packet.rss_hash}
        Rss queue : {packet.rss_queue}
        hw ptype : {packet.hw_ptype}
        sw ptype : {packet.sw_ptype}
        l2_len : {packet.l2_len}, inner_l2_len : {packet.inner_l2_len}
        l3_len : {packet.l3_len}, inner_l3_len : {packet.inner_l3_len}
        l4_len : {packet.l4_len},Receive queue : {packet.receive_queue}
        ol_flags : {packet.ol_flags}
        ============================================================""")


if __name__ == '__main__':
    packets_info_list = []
    file_content = open_file('packets.txt')
    extracted_packets = get_packets_info(file_content,
                                         SEARCH_PATTERN)
    print_packets_info(extracted_packets)
