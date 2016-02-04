/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2014 Roberto Resoli - Servizio Sistema Informativo, Comune di Trento.
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
package it.trento.comune.j4sign.cms.utils;



import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



public class SignedStreamerServlet extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		
		
		CMSVerifier cmsVerifier = (CMSVerifier) request.getSession()
				.getAttribute("CMS_VERIFIER");

		String spath = request.getServletPath();

		boolean error = false;

		if (cmsVerifier != null) {

			byte[] data = null;

			if (spath.equals("/signed")) {

				// request.getSession().removeAttribute("CMS_VERIFIER");

				data = cmsVerifier.getCmsSignedData().getEncoded();
				response.setContentType("application/pkcs7-mime");

			}
			if (spath.equals("/content")) {

				data = cmsVerifier.getCMSContent();
				response.setContentType("application/pdf");

			}

			if (data != null) {
				response.setContentLength(data.length);

				InputStream dataStream = new ByteArrayInputStream(data);
				OutputStream out = response.getOutputStream();
				byte[] buffer = new byte[1024];

				int bytesRead = 0;
				while ((bytesRead = dataStream.read(buffer, 0, buffer.length)) >= 0)
					out.write(buffer, 0, bytesRead);

				dataStream.close();
				out.flush();
			} else
				error = true;
		} else
			error = true;

		if (error) {
			response.setContentType("text/plain");
			response.getWriter().print(
					"Errore nel recupero del documento firmato");
		}

	}

}
