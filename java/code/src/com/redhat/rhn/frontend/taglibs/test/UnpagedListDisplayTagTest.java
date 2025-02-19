/*
 * Copyright (c) 2009--2014 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.frontend.taglibs.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.redhat.rhn.common.db.datasource.DataResult;
import com.redhat.rhn.common.util.test.CSVWriterTest;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.taglibs.ListTag;
import com.redhat.rhn.frontend.taglibs.UnpagedListDisplayTag;
import com.redhat.rhn.testing.MockObjectTestCase;
import com.redhat.rhn.testing.RhnMockJspWriter;
import com.redhat.rhn.testing.RhnMockServletOutputStream;
import com.redhat.rhn.testing.TestUtils;

import org.jmock.Expectations;
import org.jmock.imposters.ByteBuddyClassImposteriser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.jsp.JspException;
import javax.servlet.jsp.PageContext;
import javax.servlet.jsp.tagext.Tag;

/**
 * UnpagedListDisplayTagTest
 */
public class UnpagedListDisplayTagTest extends MockObjectTestCase {
    private UnpagedListDisplayTag ldt;
    private ListTag lt;

    private HttpServletRequest request;
    private HttpServletResponse response;
    private PageContext context;
    private RhnMockJspWriter writer;

    @BeforeEach
    public void setUp() {
        setImposteriser(ByteBuddyClassImposteriser.INSTANCE);
        TestUtils.disableLocalizationLogging();

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        context = mock(PageContext.class);
        writer = new RhnMockJspWriter();

        ldt = new UnpagedListDisplayTag();
        lt = new ListTag();
        ldt.setPageContext(context);
        ldt.setParent(lt);

        lt.setPageList(new DataResult<>(CSVWriterTest.getTestListOfMaps()));

        context().checking(new Expectations() { {
            atLeast(1).of(context).getOut();
            will(returnValue(writer));
            atLeast(1).of(context).getRequest();
            will(returnValue(request));
            atLeast(1).of(context).setAttribute("current", null);
        } });
    }

    @Test
    public void testTitle() throws JspException {
        context().checking(new Expectations() { {
            atLeast(1).of(context).popBody();
            atLeast(1).of(context).pushBody();
            atLeast(1).of(request).getParameter(RequestContext.LIST_DISPLAY_EXPORT);
            will(returnValue(null));
            atLeast(1).of(request).getParameter(RequestContext.LIST_SORT);
            will(returnValue(null));
        } });

        writer.setExpectedData(EXPECTED_HTML_OUT_WITH_TITLE);

        ldt.setTitle("Inactive Systems");
        int tagval = ldt.doStartTag();
        assertEquals(Tag.EVAL_BODY_INCLUDE, tagval);
        tagval = ldt.doEndTag();
        ldt.release();
        assertEquals(Tag.EVAL_PAGE, tagval);
    }

    @AfterEach
    public void tearDown() {
        TestUtils.enableLocalizationLogging();
    }

    @Test
    public void testTag() throws Exception {
        context().checking(new Expectations() { {
            atLeast(1).of(context).popBody();
            atLeast(1).of(context).pushBody();
            atLeast(1).of(request).getParameter(RequestContext.LIST_DISPLAY_EXPORT);
            will(returnValue("2"));
            atLeast(1).of(request).getParameter(RequestContext.LIST_SORT);
            will(returnValue("column2"));
            atLeast(1).of(request).getParameter(RequestContext.SORT_ORDER);
            will(returnValue(RequestContext.SORT_ASC));

        } });
        ldt.setExportColumns("column1,column2,column3");
        writer.setExpectedData(EXPECTED_HTML_OUT);
        int tagval = ldt.doStartTag();
        assertEquals(tagval, Tag.EVAL_BODY_INCLUDE);
        tagval = ldt.doEndTag();
        ldt.release();
        assertEquals(tagval, Tag.EVAL_PAGE);
    }

    @Test
    public void testExport() throws Exception {
        RhnMockServletOutputStream out = new RhnMockServletOutputStream();
        context().checking(new Expectations() { {
            atLeast(1).of(request).getParameter(RequestContext.LIST_DISPLAY_EXPORT);
            will(returnValue("1"));
            atLeast(1).of(context).getResponse();
            will(returnValue(response));
            atLeast(1).of(response).reset();
        } });
        context().checking(CSVMockTestHelper.getCsvExportParameterExpectations(response,
                out));
        ldt.setExportColumns("column1,column2,column3");
        int tagval = ldt.doStartTag();
        assertEquals(tagval, Tag.SKIP_PAGE);
        tagval = ldt.doEndTag();
        ldt.release();
        assertEquals(tagval, Tag.SKIP_PAGE);
        assertEquals(EXPECTED_CSV_OUT, out.getContents());
    }

    private static final String EXPECTED_HTML_OUT =
        "<div class=\"spacewalk-list\"><div class=\"panel panel-default\">" +
        "<table class=\"table table-striped\"><thead><tr></tbody></table>\n" +
        "</div>\n" +
        "</div>\n";


    private static final String EXPECTED_HTML_OUT_WITH_TITLE =
        "<div class=\"spacewalk-list\"><div class=\"panel panel-default\">" +
        "<div class=\"panel-heading\"><h4 class=\"panel-title\">**Inactive Systems**</h4>" +
        "<div class=\"spacewalk-list-head-addons\">" +
        "<div class=\"spacewalk-list-head-addons-extra\"></div>" +
        "</div></div><table class=\"table table-striped\"><thead><tr></tbody></table>\n" +
        "</div>\n" +
        "</div>\n";

    private static final String EXPECTED_CSV_OUT =
        "**column1**,**column2**,**column3**\n" +
        "cval1-0,cval2-0,cval3-0\n" +
        "cval1-1,cval2-1,cval3-1\n" +
        "cval1-2,cval2-2,cval3-2\n" +
        "cval1-3,cval2-3,cval3-3\n" +
        "cval1-4,cval2-4,cval3-4\n" +
        "cval1-5,cval2-5,cval3-5\n" +
        "cval1-6,cval2-6,cval3-6\n" +
        "cval1-7,cval2-7,cval3-7\n" +
        "cval1-8,cval2-8,cval3-8\n" +
        "cval1-9,cval2-9,cval3-9\n";
}
