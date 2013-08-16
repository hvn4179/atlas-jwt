package com.atlassian.jwt.util;

import com.google.common.collect.Lists;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
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

    public static void post(String url, Map<String, String> paramMap, Consumer<HttpResponse> consumer) throws IOException
    {
        HttpPost post = new HttpPost(url);
        List<NameValuePair> params = Lists.newArrayList();
        for (Map.Entry<String, String> entry : paramMap.entrySet())
        {
            params.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
        }
        post.setEntity(new UrlEncodedFormEntity(params));
        consume(client().execute(post), consumer);
    }

    public static void delete(String url, Consumer<HttpResponse> consumer) throws IOException
    {
        HttpDelete delete = new HttpDelete(url);
        consume(client().execute(delete), consumer);
    }

    public static void get(String url, Consumer<HttpResponse> consumer) throws IOException
    {
        HttpGet get = new HttpGet(url);
        consume(client().execute(get), consumer);
    }

    private static void consume(HttpResponse response, Consumer<HttpResponse> consumer) throws IOException
    {
        consumer.consume(response);
        EntityUtils.consume(response.getEntity());
    }

}
