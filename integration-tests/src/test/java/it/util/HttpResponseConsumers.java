package it.util;

import com.atlassian.jwt.util.Consumer;
import org.apache.http.HttpResponse;

import static junit.framework.Assert.assertEquals;

public class HttpResponseConsumers
{
    public static Consumer<HttpResponse> expectStatus(final int statusCode) {
        return new Consumer<HttpResponse>()
        {
            @Override
            public void consume(HttpResponse httpResponse)
            {
                assertEquals(statusCode, httpResponse.getStatusLine().getStatusCode());
            }
        };
    }


}
