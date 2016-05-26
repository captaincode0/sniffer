/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package linuxsniffer;

import javax.swing.JComponent;
import javax.swing.JTextArea;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author captaincode
 */
public class PacketCapture {
    private int snaplen;
    private int flags;
    private int timeout;
    private Pcap pcap;
    private JComponent component;
    private StringBuilder errbuff;
    private PcapIf device;
    
    public PacketCapture(int snaplen, int flags, int timeout, JComponent component, PcapIf device){
        this.snaplen = snaplen;
        this.flags = flags;
        this.timeout = timeout;
        this.component = component;
        this.errbuff = new StringBuilder();
        this.device = device;
        this.pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuff);
    }

    public JComponent getComponent() {
        return component;
    }

    public void setComponent(JComponent component) {
        this.component = component;
    }
    
    public void run(){
        if(this.pcap == null){
            System.err.printf("Error while opening device for capture: "+this.errbuff.toString());
            return;
        }
        
        System.out.println("Capturing packages on "+this.device.getName());
        
        PcapPacketHandler<String> jPacketHandler = new PcapPacketHandler<String>(){
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                byte[] data = packet.getByteArray(0, packet.size());
                
                byte[] sourceIP = new byte[4];
                byte[] destIP = new byte[4];
                
                Ip4 ip = new Ip4();
                
                if(packet.hasHeader(ip) == false)
                    return;
                
                sourceIP = ip.source();
                destIP = ip.destination();
                
                String sourceIPv4 = org.jnetpcap.packet.format.FormatUtils.ip(sourceIP),
                        destinationIPv4 = org.jnetpcap.packet.format.FormatUtils.ip(destIP);
                
                String sniffertext = "Source IP Address: "+sourceIPv4+", Destination IP Address "+destinationIPv4+", capture lenght: "+String.valueOf(packet.getCaptureHeader().caplen());
                print(sniffertext);
            }
        };
        
        pcap.loop(-1, jPacketHandler, "jNetPcap");
        pcap.close();
    }
    
    public void print(String text){
        text += "\n"; 
        
        if(this.component != null){
            //implementation for your component
            JTextArea tmptextarea = (JTextArea) this.component;
            tmptextarea.append(text);
        }    
        else
            System.out.println(text);
    }
}
