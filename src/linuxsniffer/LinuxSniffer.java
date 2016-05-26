/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package linuxsniffer;

import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author captaincode
 */
public class LinuxSniffer implements Capturable{
    private NetworkInterfaces interfaces;
    
    public LinuxSniffer(){
        this.interfaces = new NetworkInterfaces();
    }
    
    public NetworkInterfaces getInterfaces() {
        return this.interfaces;
    }
    
    public String[] getInterfaceList(){
        return this.interfaces.pack();
    }
    
    @Override
    public void capture(PacketCapture pcapture){
        pcapture.run();
    }
    
    /**
     * @param args the command line arguments
     */
    /*
    public static void main(String[] args) {
        //Terminal implementation
        LinuxSniffer sniffer = new LinuxSniffer();
        NetworkInterfaces netifaces = sniffer.getInterfaces();
        for(String ethface:netifaces.pack())
            //do whatever you want with te current interface item in list
        
        List<PcapIf> list = netifaces.getAlldevs();
        PacketCapture pcapture = new PacketCapture(64 * 1024, Pcap.MODE_PROMISCUOUS, 5*1000, null, list.get(7));
        pcapture.run();
    }
    */
    
    
}
