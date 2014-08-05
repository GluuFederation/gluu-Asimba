package org.asimba.wa.integrationtest.client.saml;

import java.util.Arrays;
import java.util.Collection;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.junit.After;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public abstract class AbstractHttpClientServerTest
{
    @Parameterized.Parameters
    public static Collection<SslContextFactory[]> parameters()
    {
        return Arrays.asList(new SslContextFactory[]{null}, new SslContextFactory[]{new SslContextFactory()});
    }


    protected SslContextFactory _sslContextFactory;
    protected String _scheme;
    protected Server _server;
    protected HttpClient _client;
    protected NetworkConnector _connector;

    public AbstractHttpClientServerTest(SslContextFactory sslContextFactory)
    {
        this._sslContextFactory = sslContextFactory;
        this._scheme = (sslContextFactory == null ? HttpScheme.HTTP : HttpScheme.HTTPS).asString();
    }

    public void start(Handler handler) throws Exception
    {
        if (_sslContextFactory != null)
        {
            _sslContextFactory.setEndpointIdentificationAlgorithm("");
            _sslContextFactory.setKeyStorePath("src/test/resources/keystore.jks");
            _sslContextFactory.setKeyStorePassword("storepwd");
            _sslContextFactory.setTrustStorePath("src/test/resources/truststore.jks");
            _sslContextFactory.setTrustStorePassword("storepwd");
        }

        if (_server == null)
            _server = new Server();
        _connector = new ServerConnector(_server, _sslContextFactory);
        _server.addConnector(_connector);
        _server.setHandler(handler);
        _server.start();

        QueuedThreadPool executor = new QueuedThreadPool();
        executor.setName(executor.getName() + "-client");
        _client = new HttpClient(_sslContextFactory);
        _client.setExecutor(executor);
        _client.start();
    }

    @After
    public void dispose() throws Exception
    {
        if (_client != null)
            _client.stop();
        if (_server != null)
            _server.stop();
        _server = null;
    }
}