package ipc;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class ARPDlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<>();
	private BaseLayer fileUnderLayer;
	private static LayerManager m_LayerMgr = new LayerManager();
	

	private JTextField ChattingWrite;

	private ArrayList<MacAndName> storageOfMacList = new ArrayList<>();

	private JTextArea IPAddressArea;
	private JPanel contentPane;
	private JButton ARPCacheSendButton;
	private JTextArea ARPCacheTextArea;
	private JButton AllDeleteButton;
	private JButton ItemDeleteButton;

	public static void getMacAddressFromARPLayer(String IPAddress, String MacAddress) {

	}

	public ARPDlg(String pName) {
		this.pLayerName = pName;
	}

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		// *********************************************
		// TCP, IP, ARP Layer add required
		// *********************************************
		
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new ARPDlg("GUI"));
		m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( +IP ( *TCP ( *GUI )  -ARP ) *ARP ) )");

		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ARPDlg frame = new ARPDlg();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public ARPDlg() {
		setTitle("TestARP");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 867, 502);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		JPanel ARPCachePanel = new JPanel();
		ARPCachePanel
				.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		ARPCachePanel.setToolTipText("");
		ARPCachePanel.setBounds(14, 12, 384, 385);
		contentPane.add(ARPCachePanel);
		ARPCachePanel.setLayout(null);

		ARPCacheTextArea = new JTextArea();
		ARPCacheTextArea.setEditable(false);
		ARPCacheTextArea.setBounds(14, 23, 356, 189);
		ARPCachePanel.add(ARPCacheTextArea);

		ItemDeleteButton = new JButton("Item Delete");
		ItemDeleteButton.addActionListener(new setAddressListener());
		ItemDeleteButton.setBounds(24, 221, 135, 33);
		ARPCachePanel.add(ItemDeleteButton);

		AllDeleteButton = new JButton("All Delete");
		AllDeleteButton.addActionListener(new setAddressListener());
		AllDeleteButton.setBounds(209, 221, 135, 33);
		ARPCachePanel.add(AllDeleteButton);

		JLabel lblNewLabel = new JLabel("IP 주소");
		lblNewLabel.setBounds(14, 316, 62, 18);
		ARPCachePanel.add(lblNewLabel);

		IPAddressArea = new JTextArea();
		IPAddressArea.setBounds(78, 314, 200, 24);
		ARPCachePanel.add(IPAddressArea);

		ARPCacheSendButton = new JButton("Send");
		ARPCacheSendButton.addActionListener(new setAddressListener());
		ARPCacheSendButton.setBounds(293, 312, 77, 27);
		ARPCachePanel.add(ARPCacheSendButton);

		JPanel ProxyARPPanel = new JPanel();
		ProxyARPPanel.setBorder(
				new TitledBorder(null, "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		ProxyARPPanel.setBounds(412, 12, 425, 260);
		contentPane.add(ProxyARPPanel);
		ProxyARPPanel.setLayout(null);

		JTextArea textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setBounds(14, 28, 397, 162);
		ProxyARPPanel.add(textArea);

		JButton AddButton = new JButton("Add");
		AddButton.addActionListener(new setAddressListener());
		AddButton.setBounds(48, 202, 135, 33);
		ProxyARPPanel.add(AddButton);

		JButton DeleteButton = new JButton("Delete");
		DeleteButton.addActionListener(new setAddressListener());
		DeleteButton.setBounds(236, 202, 135, 33);
		ProxyARPPanel.add(DeleteButton);

		JPanel GratuitousARPPanel = new JPanel();
		GratuitousARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		GratuitousARPPanel.setBounds(412, 284, 425, 110);
		contentPane.add(GratuitousARPPanel);
		GratuitousARPPanel.setLayout(null);

		JLabel lblHw = new JLabel("H/W 주소");
		lblHw.setBounds(14, 47, 71, 18);
		GratuitousARPPanel.add(lblHw);

		JTextArea HWAddressArea = new JTextArea();
		HWAddressArea.setBounds(99, 45, 202, 24);
		GratuitousARPPanel.add(HWAddressArea);

		JButton GratuitousARPSendButton = new JButton("Send");
		GratuitousARPSendButton.addActionListener(new setAddressListener());
		GratuitousARPSendButton.setBounds(334, 43, 77, 27);
		GratuitousARPPanel.add(GratuitousARPSendButton);

		JButton QuitButton = new JButton("종료");
		QuitButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		QuitButton.setBounds(293, 406, 105, 27);
		contentPane.add(QuitButton);

		JButton CancelButton = new JButton("취소");
		CancelButton.setBounds(412, 406, 105, 27);
		contentPane.add(CancelButton);
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
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}

	private class MacAndName {
		public byte[] macAddress;
		public String macName;
		public String macAddressStr;
		public int portNumber;

		public MacAndName(byte[] macAddress, String macName, String macAddressStr, int portNumberOfMac) {
			this.macAddress = macAddress;
			this.macName = macName;
			this.macAddressStr = macAddressStr;
			this.portNumber = portNumberOfMac;
		}
	}

	class setAddressListener implements ActionListener {

		@Override
		public void actionPerformed(ActionEvent e) {
			// TODO Auto-generated method stub
			if (e.getSource() == ARPCacheSendButton) {
				String IPAddress = IPAddressArea.getText();
				if (!IPAddress.equals("")) {
					IPAddress = IPAddress + "          ??????????                         Incomplete\n";
					ARPCacheTextArea.append(IPAddress);
					IPAddressArea.setText("");
				}
			}
			if (e.getSource() == AllDeleteButton) {
				if (ARPCacheTextArea.getText().equals("")) {
					JOptionPane.showMessageDialog(null, "삭제할 ARP가 존재하지 않습니다.");
					return;
				}
				int result = JOptionPane.showConfirmDialog(null, "모든 Cache를 삭제하시겠습니까?", "Cache Delete",
						JOptionPane.OK_CANCEL_OPTION);
				if (result == 0) {
					ARPCacheTextArea.setText("");
				}
			}
			if (e.getSource() == ItemDeleteButton) {
				if (ARPCacheTextArea.getText().equals("")) {
					JOptionPane.showMessageDialog(null, "삭제할 ARP가 존재하지 않습니다.");
					return;
				}
				String indexValue = JOptionPane.showInputDialog(null, "삭제할 Cache의 인덱스를 입력해주세요(Index : 1부터 시작)",
						"Cache Delete", JOptionPane.OK_CANCEL_OPTION);
				int indexValueInteger = 0;
				if (indexValue != null) {
					indexValueInteger = Integer.parseInt(indexValue);
				}
				String[] ARPCacheList = ARPCacheTextArea.getText().split("\n");
				String result = "";
				for(int i = 0; i < ARPCacheList.length; i++) {
					if(i != indexValueInteger -1) {
						result = result + ARPCacheList[i] + "\n";
					}
				}
				ARPCacheTextArea.setText(result);
			}
		}
	}
}
