package it;

import com.atlassian.jira.pageobjects.JiraTestedProduct;
import com.atlassian.pageobjects.Defaults;
import com.atlassian.pageobjects.TestedProduct;
import it.util.TestedProductHolder;

/**
 *
 */
public abstract class AbstractBrowserlessTest
{
    protected final String baseUrl;

    public AbstractBrowserlessTest()
    {
        this(JiraTestedProduct.class);
    }

    public AbstractBrowserlessTest(Class<? extends TestedProduct> testedProductClass)
    {
        if (System.getProperty("baseurl") == null)
        {
            Defaults defs = testedProductClass.getAnnotation(Defaults.class);
            baseUrl = "http://localhost:" + defs.httpPort() + defs.contextPath();
        }
        else
        {
            baseUrl = TestedProductHolder.INSTANCE.getProductInstance().getBaseUrl();
        }
    }

    protected String registrationResource() {
        return baseUrl + "/rest/jwt-test/latest/register";
    }

}
