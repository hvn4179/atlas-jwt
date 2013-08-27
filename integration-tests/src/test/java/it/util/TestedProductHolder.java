package it.util;

import com.atlassian.jira.pageobjects.JiraTestedProduct;
import com.atlassian.pageobjects.TestedProduct;
import com.atlassian.pageobjects.TestedProductFactory;

/**
 *
 */
public class TestedProductHolder
{
    public static final TestedProduct INSTANCE;

    static
    {
        INSTANCE = TestedProductFactory.create(JiraTestedProduct.class);
    }
}
