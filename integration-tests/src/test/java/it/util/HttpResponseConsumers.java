package it.util;

import com.atlassian.jwt.util.Consumer;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;

import java.io.IOException;

import static junit.framework.Assert.assertEquals;

public class HttpResponseConsumers
{
    public static Consumer<HttpResponse, RuntimeException> expectStatus(final int statusCode)
    {
        return new Consumer<HttpResponse, RuntimeException>()
        {
            @Override
            public void consume(HttpResponse httpResponse)
            {
                assertEquals(statusCode, httpResponse.getStatusLine().getStatusCode());
            }
        };
    }

    public static Consumer<HttpResponse, IOException> expectBody(final String expected)
    {
        return new Consumer<HttpResponse, IOException>()
        {
            @Override
            public void consume(HttpResponse httpResponse) throws IOException
            {
                String body = IOUtils.toString(httpResponse.getEntity().getContent());
                assertEquals(expected, body);
            }
        };
    }


}
