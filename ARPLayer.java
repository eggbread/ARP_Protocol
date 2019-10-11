package ipc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;



public class ARPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
    public HashMap<byte[], byte[]> arp_table = new HashMap<>();
	public _ARP_HEADER arp_Header = new _ARP_HEADER();
	public HashMap<byte[], byte[]> proxy_table = new HashMap<>();

    private class _ARP_ADDR {
        private byte[] mac_addr = new byte[6];
        private byte[] ip_addr = new byte[4];

        public _ARP_ADDR() {
            for (int indexOfAddr = 0; indexOfAddr < mac_addr.length; ++indexOfAddr) {
                this.mac_addr[indexOfAddr] = (byte) 0x00;
            }
            for (int indexOfAddr = 0; indexOfAddr < ip_addr.length; ++indexOfAddr) {
                this.ip_addr[indexOfAddr] = (byte) 0x00;
            }
        }
    }
	private class _ARP_HEADER {
		byte is_checked;//arp이면 06 ip이면 08
        byte[] arp_mac_type;
        byte[] arp_ip_type;
        byte arp_mac_addr_len;
        byte arp_ip_addr_len;
        byte[] arp_opcode;
        _ARP_ADDR arp_srcaddr;
        _ARP_ADDR arp_dstaddr;

        public _ARP_HEADER() {
           this.is_checked=0x00;
           this.arp_mac_type = new byte[2];
           this.arp_ip_type = new byte[2];
           this.arp_mac_addr_len = 0x06;
           this.arp_ip_addr_len = 0x04;
           this.arp_opcode = new byte[2];
           this.arp_srcaddr = new _ARP_ADDR();
           this.arp_dstaddr = new _ARP_ADDR();
        }
    }//내부 클래스
    public boolean containMacAddress(byte[] input) {
    	return this.arp_table.containsKey(input);
    }
    public byte[] getMacAddress(byte[] input) {
    	return this.arp_table.get(input);
    }
	@Override
	public synchronized boolean Send(byte[] input, int length) {
		//IPLayer가 arp테이블을 봤는데 없어서 일로 옴
		//ARP를 만든다.
		byte[] src_Ip_Address;//여기서 input의 ip넣고
		byte[] src_Mac_Address;//여기서 내 mac넣고
		byte[] dst_Ip_Address;//여기서 input의 ip넣고
		this.arp_Header.arp_srcaddr.ip_addr=src_Ip_Address;
		this.arp_Header.arp_srcaddr.mac_addr=src_Mac_Address;
		this.arp_Header.arp_dstaddr.ip_addr=dst_Ip_Address;
		//dst mac은 0
		byte[] headerAddedArray=ObjToByte_Send(arp_Header, (byte)0x06,(byte)0x01);//ARP이고 요청인 헤더
		
		
//		if(arp_table.containsKey(dst_Ip)) {//아는경우 ethernet type 0800 헤더생성 
//			headerAddedArray=input;
////			((EthernetLayer)this.GetUnderLayer()).setDstAddress(dst_Ip);
////			return this.GetUnderLayer().Send(headerAddedArray,)
//		}else {//모르는 경우 0806 상대 mac주소를 모르는 헤더 생성
//			headerAddedArray=this.ObjToByte_Send(arp_Header, input);
//		}
		
		this.GetUnderLayer().Send(headerAddedArray, headerAddedArray.length);
		//EthernetLayer의 send호출
		return false;
		
	}
	
	@Override
	public synchronized boolean Receive(byte[] input) {
		byte is_checked = input[0];
		byte[] hardware_type=Arrays.copyOfRange(input, 1,3);
		byte[] protocol_type=Arrays.copyOfRange(input, 3,5);
		byte length_mac_address = input[5];
		byte length_ip_address = input[6];
		byte[] opcode = Arrays.copyOfRange(input, 7, 9);
		byte[] src_mac_address=Arrays.copyOfRange(input, 9, 15);
		byte[] src_ip_address=Arrays.copyOfRange(input, 15, 19);
		byte[] dst_mac_address=new byte[6];//내 Mac주소 ****고쳐야함****
		byte[] dst_ip_address=Arrays.copyOfRange(input, 25, 29);
		
		if(opcode[0]==0x00&opcode[1]==0x01) {//ARP 요청 받음
			this.arp_table.put(src_ip_address, src_mac_address);//table에 추가
			_ARP_HEADER response_header = new _ARP_HEADER();//보낼 헤드
			if(dst_ip_address==this.arp_Header.arp_srcaddr.ip_addr) {//내 ip로 옴
				response_header.arp_srcaddr.mac_addr=dst_mac_address;//내 mac주소
				response_header.arp_srcaddr.ip_addr=dst_ip_address;
				response_header.arp_dstaddr.mac_addr=src_mac_address;
				response_header.arp_dstaddr.ip_addr=src_ip_address;
			}else {//내 ip로 안옴
				if(this.proxy_table.containsKey(dst_ip_address)) {//연결된 proxy이다 ****여기부터 해라*****
					response_header.arp_srcaddr.mac_addr=this.proxy_table.get(dst_ip_address);//proxy mac주소
					response_header.arp_srcaddr.ip_addr=dst_ip_address;
					response_header.arp_dstaddr.mac_addr=src_mac_address;
					response_header.arp_dstaddr.ip_addr=src_ip_address;
				}else {//proxy아님
					return false;//proxy아니고 내꺼도 아니니 버린다
				}
			}
			byte[] response_arp=ObjToByte_Send(response_header, (byte)0x06, (byte)0x02);
			this.GetUnderLayer().Send(response_arp,response_arp.length);
		}else if(opcode[0]==0x00&opcode[1]==0x02) {//요청이 돌아옴
			this.arp_table.put(src_ip_address, src_mac_address);//요청받은거 테이블에 저장
		}
		return false;
	}
	public byte[] ObjToByte_Send(_ARP_HEADER Header,byte is_checked,byte opcode) {
	      byte[] buf = new byte[29];
	      byte[] src_mac = Header.arp_srcaddr.mac_addr;
	      byte[] src_ip = Header.arp_srcaddr.ip_addr;
	      byte[] dst_mac = Header.arp_dstaddr.mac_addr;
	      byte[] dst_ip = Header.arp_dstaddr.ip_addr;

	      buf[0] = is_checked;
	      buf[1] = 0x00;
	      buf[2] = 0x01;//Hard
	      buf[3] = 0x08;
	      buf[4] = 0x00;//protocol
	      buf[5] = Header.arp_mac_addr_len;//1바이트
	      buf[6] = Header.arp_ip_addr_len;//2바이트
	      buf[7] = 0x00;
	      buf[8] = opcode;
	      System.arraycopy(src_mac, 0, buf, 9, 6);//6바이트
	      System.arraycopy(src_ip, 0, buf, 15, 4);//4바이트
	      System.arraycopy(dst_mac, 0, buf, 19, 6);//6바이트
	      System.arraycopy(dst_ip, 0, buf, 25, 4);//4바이트
	      

	      return buf;
	   }
    public ARPLayer(String name) {
    	this.pLayerName = name;
    }


    @Override
    public String GetLayerName() {
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);//layer異붽�
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }

}
