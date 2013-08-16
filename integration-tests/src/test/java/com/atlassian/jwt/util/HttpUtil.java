package com.atlassian.jwt.util;

import com.google.common.collect.Lists;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class HttpUtil
{

    private static HttpClient httpClient;

    public static HttpClient client()
    {
        return httpClient == null ? httpClient = new DefaultHttpClient() : httpClient;
    }

    public static <E extends Exception> void post(String url, Map<String, String> paramMap, Consumer<HttpResponse, E> consumer) throws IOException, E
    {
        HttpPost post = new HttpPost(url);
        List<NameValuePair> params = Lists.newArrayList();
        for (Map.Entry<String, String> entry : paramMap.entrySet())
        {
            params.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
        }
        post.setEntity(new UrlEncodedFormEntity(params));
        execute(post, consumer);
    }

    public static <E extends Exception> void delete(String url, Consumer<HttpResponse, E> consumer) throws IOException, E
    {
        execute(new HttpDelete(url), consumer);
    }

    public static <E extends Exception> void get(String url, Consumer<HttpResponse, E> consumer) throws IOException, E
    {
        execute(new HttpGet(url), consumer);
    }

    private static <E extends Exception> void execute(HttpUriRequest request, Consumer<HttpResponse, E> consumer) throws IOException, E
    {
        HttpResponse response = null;
        try {
            response = client().execute(request);
            consumer.consume(response);
            EntityUtils.consume(response.getEntity());
        } catch (AssertionError e) {
            // dump req/resp info in the event of failure
            logRequest(request);
            if (response != null) {
                logResponse(response);
            }
            throw e;
        }
    }

    private static void logRequest(HttpUriRequest req)
    {
        StringBuilder sb = new StringBuilder()
                .append("---- Dumping request ----\n")
                .append(req.getMethod()).append(" ").append(req.getURI()).append("\n")
                .append("---- Headers ----\n");
        for (Header header : req.getAllHeaders()) {
            sb.append(header.getName()).append(": ").append(header.getValue()).append("\n");
        }
        System.out.println(sb.toString());
    }

    private static void logResponse(HttpResponse resp)
    {
        StringBuilder sb = new StringBuilder()
                .append("---- Dumping response ----\n")
                .append(resp.getStatusLine().getStatusCode()).append(" ").append(resp.getStatusLine().getReasonPhrase()).append("\n")
                .append("---- Headers ----\n");
        for (Header header : resp.getAllHeaders()) {
            sb.append(header.getName()).append(": ").append(header.getValue()).append("\n");
        }
        System.out.println(sb.toString());
    }

}
