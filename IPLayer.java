package ipc;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _IP_Header ip_header = new _IP_Header();

    private static LayerManager m_LayerMgr = new LayerManager();

    public IPLayer(String pName) {
        pLayerName = pName;

        SetIpSrcAddress(GetIpAddress());//내 IP주소 세팅
    }

    public byte[] RemoveCappHeader(byte[] input, short length) {

        byte[] temp = new byte[length - 20];
        System.arraycopy(input, 20, temp, 0, length - 20);
        return temp;
    }

    public boolean Send(byte[] input, short length) {
        byte[] temp = ObjToByte20(this.ip_header, input, length);

        return this.GetUnderLayer().Send(temp, length + 20);    //ARP Layer에게 전달
    }

    public byte[] ObjToByte20(_IP_Header ip_header, byte[] input, short length) {

        byte[] buf = new byte[length + 20];

        buf[0] = ip_header.ip_verlen;
        buf[1] = ip_header.ip_tos;
        buf[2] |= (byte) ((length >> 8) & 0xFF);
        buf[3] |= (byte) (length & 0xFF);

        buf[4] |= (byte) ((ip_header.ip_id >> 8) & 0xFF);
        buf[5] |= (byte) (ip_header.ip_id & 0xFF);

        buf[6] |= ((ip_header.ip_fragoff >> 8) & 0xFF);
        buf[7] |= (ip_header.ip_fragoff & 0xFF);

        buf[8] = ip_header.ip_ttl;
        buf[9] = ip_header.ip_proto;

        buf[10] |= ((ip_header.ip_cksum >> 8) & 0xFF);
        buf[11] |= (ip_header.ip_cksum & 0xFF);

        System.arraycopy(ip_header.ip_srcaddr, 0, buf, 12, 4);
        System.arraycopy(ip_header.ip_dstaddr, 0, buf, 16, 4);

        return buf;
    }

    public synchronized boolean Receive(byte[] input) {
        // IP 타입 체크
        if (this.ip_header.ip_verlen != input[0] || this.ip_header.ip_tos != input[1]
                || this.ip_header.ip_id != (short) ((input[4] & 0xFF) << 8 + input[5] & 0xFF)
                || this.ip_header.ip_proto != input[9])
            return false;


        for (int i = 0; i < 4; i++)
            if (this.ip_header.ip_srcaddr.addr[i] != input[16 + i]) { //input의 target IP주소가 나의 IP주소와 일치하는지 확인
                //return this.GetUnderLayer().proxySend(input, tot_len); //일치하지 않으면 프록시
            }

        //일치하면 demultiplex하고 상위 레이어로 올림
        short tot_len = (short) (((input[2] & 0xFF) << 8) + input[3] & 0xFF);
        byte[] temp = RemoveCappHeader(input, tot_len);
        return this.GetUpperLayer(0).Receive(temp);
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
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);

    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }

    // src IP주소 세팅
    public void SetIpSrcAddress(byte[] srcAddress) {
        ip_header.ip_srcaddr.addr = srcAddress;
    }

    // dst IP주소 세팅
    public void SetIpDstAddress(byte[] dstAddress) {
        ip_header.ip_dstaddr.addr = dstAddress;

    }

    public byte[] GetIpAddress() {

        InetAddress local = null;
        try {
            local = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        String[] hostAddressInString = local.getHostAddress().split("[.]");

        byte[] temp = new byte[4];
        for (int i = 0; i < 4; i++)
            temp[i] = Byte.parseByte(hostAddressInString[i]);

        return temp;
    }

    // Header 자료구조
    private class _IP_Header {
        byte ip_verlen; // ip version (1byte)   index 0
        byte ip_tos; // type of service (1byte) index 1
        short ip_len; // total packet length (2byte) index 2~3
        short ip_id; // datagram Identification(2byte) index 4~5
        short ip_fragoff;// fragment offset (2byte)	index 6~7
        byte ip_ttl; // time to live in gateway hops (1byte) index 8
        byte ip_proto; // IP protocol (1byte) index 9
        short ip_cksum; // header checksum (2byte) index 10 11
        // 0~11 index

        _IP_ADDR ip_srcaddr;// source IP address (4byte) 12~15 index
        _IP_ADDR ip_dstaddr;// destination IP address (4byte) 16~19 index

        // byte ip_data[]; //variable length data (variable)

        public _IP_Header() {
            this.ip_verlen = 4;
            this.ip_tos = 0;
            this.ip_len = 0;
            this.ip_id = 0;
            this.ip_fragoff = 0;
            this.ip_ttl = 0;
            this.ip_proto = 0;
            this.ip_cksum = 0;
            this.ip_srcaddr = new _IP_ADDR();
            this.ip_dstaddr = new _IP_ADDR();

        }

        // 헤더의 IP주소 자료구조
        private class _IP_ADDR {
            private byte[] addr = new byte[4];

            public _IP_ADDR() {
                this.addr[0] = 0;
                this.addr[1] = 0;
                this.addr[2] = 0;
                this.addr[3] = 0;
            }
        }
    }
}
