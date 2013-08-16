package it.util;

import com.google.common.collect.Lists;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

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

    public static HttpResponse post(String url, Map<String, String> paramMap) throws IOException
    {
        HttpPost post = new HttpPost(url);
        List<NameValuePair> params = Lists.newArrayList();
        for (Map.Entry<String, String> entry : paramMap.entrySet())
        {
            params.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
        }
        post.setEntity(new UrlEncodedFormEntity(params));
        return client().execute(post);
    }

    public static HttpResponse get(String url) throws IOException
    {
        HttpGet get = new HttpGet(url);
        return client().execute(get);
    }

}
