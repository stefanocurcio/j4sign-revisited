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
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/pcsc/CardInfo.java,v 1.1 2004/12/27 11:14:32 resoli Exp $
 * $Revision: 1.1 $
 * $Date: 2004/12/27 11:14:32 $
 */
package it.trento.comune.j4sign.pcsc;

import java.util.Hashtable;

/**
 * Stores informations about a card.
 * 
 * @author Roberto Resoli
 *
 */

public class CardInfo {
    private Hashtable infos = new Hashtable();

    /**
     * Adds the given attribute with corresponding value.
     * 
     * @param attribute key for retrieving the information.
     * @param value information to store.
     */
    public void addProperty(String attribute, Object value) {
        infos.put(attribute, value);
    }

    /**
     * Retrieves the value for the given attribute.
     * 
     * @param attribute key to search.
     * @return the value for the given attribute, <code>null</code> if not found.
     */
    public String getProperty(String attribute) {
        return (String) infos.get(attribute);
    }

}