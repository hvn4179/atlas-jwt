package com.atlassian.jwt.util;

import java.io.IOException;
import java.net.ServerSocket;

public class ServerUtil
{
    public static int pickFreePort()
    {
        ServerSocket socket = null;
        try
        {
            socket = new ServerSocket(0);
            return socket.getLocalPort();
        }
        catch (IOException e)
        {
            throw new RuntimeException("Error opening socket", e);
        }
        finally
        {
            if (socket != null) {
                try
                {
                    socket.close();
                }
                catch (IOException e)
                {
                    // ignore
                }
            }
        }
    }
}
