/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2004 Roberto Resoli - Servizio Sistema Informativo - Comune di Trento.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
/*
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/pcsc/PCSCHelper.java,v 1.6 2014/05/21 14:11:00 resoli Exp $
 * $Revision: 1.6 $
 * $Date: 2014/05/21 14:11:00 $
 */

package it.trento.comune.j4sign.pcsc;



import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import java.util.Vector;


import com.ibm.opencard.terminal.pcsc10.OCFPCSC1;
import com.ibm.opencard.terminal.pcsc10.Pcsc10Constants;
import com.ibm.opencard.terminal.pcsc10.PcscException;
import com.ibm.opencard.terminal.pcsc10.PcscReaderState;
import java.io.*;

/**
 * A java class for detecting SmartCard tokens and readers via PCSC.
 *
 * @author Roberto Resoli
 */
public class PCSCHelper {
    private Hashtable cardInfos = new Hashtable();
    private Hashtable cards = new Hashtable();

    /** The reference to the PCSC ResourceManager for this card terminal. */
    private OCFPCSC1 pcsc;

    /** The context to the PCSC ResourceManager */
    private int context = 0;

    /** The state of this card terminal. */
    private boolean closed;

    /** Is a card inserted currently? */
    private boolean cardInserted;

    /** The cardHandle */
    private int cardHandle = 0;

    /* states returned by SCardGetStatusChange */
    private static final int SCARD_STATE_MUTE = 0x200;

    private static final int SCARD_STATE_PRESENT = 0x020;

    /** The <tt>ATR</tt> of the presently inserted card. */
    private byte[] cachedATR;

    private String type = null;

    private String[] readers = null;


    public PCSCHelper(boolean loadLib) {

        try {
            System.out.println("connect to PCSC 1.0 resource manager");

            // load native library
            if (loadLib) {
                OCFPCSC1.loadLib();
            }

            pcsc = new OCFPCSC1();

            readers = pcsc.SCardListReaders(null);

            this.type = "PCSC10";

            /* connect to the PCSC resource manager */
            context = pcsc.SCardEstablishContext(Pcsc10Constants.SCARD_SCOPE_USER);

            System.out.println("Driver initialized");

            loadProperties();

        } catch (PcscException e) {
            System.out.println(e);
        }

        /* add one slot */
        //this.addSlots(1);
    }

    private void loadProperties() {

        System.out.println("Loading properties...");

        Properties prop = new Properties();

        InputStream propertyStream=null;
        String scPropertiesFile = null;
        
        String osName = System.getProperty("os.name");
        if (osName.toLowerCase().indexOf("win") > -1) {
            scPropertiesFile = "scWin.properties";
        }
        if (osName.toLowerCase().indexOf("linux") > -1) {
            scPropertiesFile = "scLinux.properties";
        }
        if (osName.toLowerCase().indexOf("mac") > -1) {
            scPropertiesFile = "scMac.properties";
        }
        if (scPropertiesFile!=null) {
            propertyStream = this.getClass().getResourceAsStream(scPropertiesFile);
        }

        if (propertyStream != null) {
            try {
                prop.load(propertyStream);

            } catch (IOException e2) {
                System.out.println(e2);
            }
            //prop.list(System.out);
        }

        Iterator i = prop.keySet().iterator();

        String currKey = null;

        int index = 0;
        int pos = -1;
        String attribute = null;
        String value = null;

        //loading propertis in a vector of CardInfo
        Vector v = new Vector();
        CardInfo ci = null;
        while (i.hasNext()) {
            currKey = (String) i.next();
            pos = currKey.indexOf(".");
            index = Integer.parseInt(currKey.substring(0, pos));
            attribute = currKey.substring(pos + 1);
            value = (String) prop.get(currKey);
            value = "atr".equals(attribute) ? value.toUpperCase() : value;

            while (index > v.size()) {
                ci = new CardInfo();
                v.addElement(ci);
            }
            ci = (CardInfo) v.get(index - 1);
            ci.addProperty(attribute, value);
        }

        //coverting vector to Hashtable (keyed by ATR)
        i = v.iterator();
        while (i.hasNext()) {
            ci = (CardInfo) i.next();
            this.cardInfos.put(ci.getProperty("atr"), ci);
            //cosa mette nella Hash Table?
            // System.out.println("ATR inserita nella Hash Table: "+ ci.getProperty("atr"));
        }

    }

    public static void main(String[] args) {
        PCSCHelper a = new PCSCHelper(true);
        a.findCards();
        System.exit(0);
    }

    public List findCards() {

        ArrayList cards = new ArrayList();

        try {
            int numReaders = getReaders().length;

            System.out.println("Found " + numReaders + " readers.");

            String currReader = null;
            for (int i = 0; i < getReaders().length; i++) {
                currReader = getReaders()[i];
                System.out.println("\nChecking card in reader '"
                                   + currReader + "'.");
                if (isCardPresent(currReader)) {
                    System.out.println("Card is present in reader '"
                                       + currReader + "' , ATR String follows:");
                    System.out.println("ATR: " + formatATR(cachedATR, " "));

                    CardInfo ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));

                    if (ci != null) {
                        cards.add(ci);

                        System.out
                                .println("\nInformations found for this card:");
                        System.out.println("Description:\t"
                                           + ci.getProperty("description"));
                        System.out.println("Manufacturer:\t"
                                           + ci.getProperty("manufacturer"));
                        System.out.println("ATR:\t\t" + ci.getProperty("atr"));
                        System.out.println("Criptoki:\t"
                                           + ci.getProperty("lib"));
                    }

                } else {
                    System.out.println("No card in reader '" + currReader
                                       + "'!");
                }
            }

        } catch (Exception e) {
            System.out.println(e);
        }
        return cards;
    }


    public List findCardsAndReaders() {

        ArrayList cardsAndReaders = new ArrayList();

        try {
            int numReaders = getReaders().length;

            //System.out.println("Found " + numReaders + " readers.");

            String currReader = null;
            CardInReaderInfo cIr = null;
            int indexToken = 0;
            for (int i = 0; i < getReaders().length; i++) {

                currReader = getReaders()[i];
                // System.out.println("\nChecking card in reader '"
                //                   + currReader + "'.");
                if (isCardPresent(currReader)) {
                    // System.out.println("Card is present in reader '"
                    //                    + currReader + "' , ATR String follows:");
                    // System.out.println("ATR: " + formatATR(cachedATR, " "));
                    CardInfo ci = new CardInfo();
                    // trova per ATR
                    ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));

                    cIr = new CardInReaderInfo(currReader, ci);
                    
                    //Have to be set by PKCS11
                    //cIr.setIndexToken(indexToken);
                    //cIr.setSlotId(indexToken);
                    cIr.setLib(ci.getProperty("lib"));
                    indexToken++;
                } else {
                    //  System.out.println("No card in reader '" + currReader
                    //                     + "'!");
                    cIr = new CardInReaderInfo(currReader, null);
                    cIr.setLib(null);
                }
                cardsAndReaders.add(cIr);
            }

        } catch (Exception e) {
            System.out.println(e);
        }
        return cardsAndReaders;
    }


    //restituisce una HashTable con chiave la lib e con oggetto una lista di CardInReaderInfo
    public Hashtable findCardsAndReadersKeyedByLib() {
        Hashtable h = new Hashtable();
        ArrayList cardsAndReaders = new ArrayList();

        try {
            int numReaders = getReaders().length;

            //System.out.println("Found " + numReaders + " readers.");

            String currReader = null;
            CardInReaderInfo cIr = null;
            int indexToken = 0;
            for (int i = 0; i < getReaders().length; i++) {

                currReader = getReaders()[i];
                // System.out.println("\nChecking card in reader '"
                //                   + currReader + "'.");
                if (isCardPresent(currReader)) {
                    // System.out.println("Card is present in reader '"
                    //                    + currReader + "' , ATR String follows:");
                    // System.out.println("ATR: " + formatATR(cachedATR, " "));
                    CardInfo ci = new CardInfo();
                    // trova per ATR
                    ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));

                    cIr = new CardInReaderInfo(currReader, ci);
                    cIr.setIndexToken(indexToken);
                    cardsAndReaders = (ArrayList) h.get(ci.getProperty("lib"));
                    if (cardsAndReaders == null) {
                        cardsAndReaders = new ArrayList();
                    }
                    cardsAndReaders.add(cIr);
                    h.put(ci.getProperty("lib"), cardsAndReaders);

                    indexToken++;
                } else {
                    //  System.out.println("No card in reader '" + currReader
                    //                     + "'!");
                    cIr = new CardInReaderInfo(currReader, null);
                    cardsAndReaders = (ArrayList) h.get("noLib");
                    if (cardsAndReaders == null) {
                        cardsAndReaders = new ArrayList();
                    }
                    cardsAndReaders.add(cIr);
                    h.put("noLib", cardsAndReaders);

                }

            }

        } catch (Exception e) {
            System.out.println(e);
        }
        return h;
    }

    public String findLibForIndexToken(int indexToken) {
        String lib = null;

        try {
            String currReader = null;
            int index = 0;
            for (int i = 0; i < getReaders().length; i++) {

                currReader = getReaders()[i];
                if (isCardPresent(currReader)) {
                    CardInfo ci = new CardInfo();
                    // trova per ATR
                    ci = (CardInfo) getCardInfos().get(
                            formatATR(cachedATR, ""));

                    if (index == indexToken) {
                        lib = ci.getProperty("lib");
                    }
                    index++;
                }

            }
        } catch (Exception e) {
            System.out.println(e);
        }
        return lib;
    }

    public String formatATR(byte[] atr, String byteSeparator) {
        int n, x;
        String w = new String();
        String s = new String();

        for (n = 0; n < atr.length; n++) {
            x = (int) (0x000000FF & atr[n]);
            w = Integer.toHexString(x).toUpperCase();
            if (w.length() == 1) {
                w = "0" + w;
            }
            s = s + w + ((n + 1 == atr.length) ? "" : byteSeparator);
        } // for
        return s;
    }


    /**
     * Check whether there is a smart card present.
     *
     * @param name
     *            Name of the reader to check.
     * @return True if there is a smart card inserted in the card terminals
     *         slot.
     */
    public synchronized boolean isCardPresent(String name) {

        // check if terminal is already closed...
        if (!closed) {

            /* fill in the data structure for the state request */
            PcscReaderState[] rState = new PcscReaderState[1];
            rState[0] = new PcscReaderState();
            rState[0].CurrentState = Pcsc10Constants.SCARD_STATE_UNAWARE;
            rState[0].Reader = name;

            try {
                /* set the timeout to 1 second */
                pcsc.SCardGetStatusChange(context, 1, rState);

                // PTR 0219: check if a card is present but unresponsive
                if (((rState[0].EventState & SCARD_STATE_MUTE) != 0)
                    && ((rState[0].EventState & SCARD_STATE_PRESENT) != 0)) {

                    System.out
                            .println("Card present but unresponsive in reader "
                                     + name);
                }

            } catch (PcscException e) {
                System.out.println("Exception:");
                System.out.println(e);
                System.out.println("Reader " + name + " is not responsive!");
            }

            cachedATR = rState[0].ATR;

            // check the length of the returned ATR. if ATR is empty / null, no
            // card is inserted
            if (cachedATR != null) {
                if (cachedATR.length > 0) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }

        } else {
            return false;
        }
        // return "no card inserted", because terminal is already closed
    }

    /**
     * @return Returns the readers.
     */
    public String[] getReaders() {
        return readers;
    }

    /**
     * @return Returns the cardInfos.
     */
    public Hashtable getCardInfos() {
        return cardInfos;
    }
}
