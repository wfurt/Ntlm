using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Threading;
using System.Threading.Tasks;


namespace NtlmTest
{
    class Program
    {
        private static NetworkCredential nc;

        static async Task Authenticate(String uri, bool useNtlm = true)
        {
            var handler = new SocketsHttpHandler();
            var client = new HttpClient(handler);
            client.DefaultRequestHeaders.Add( "Accept", "*/*");

            var ntlm = new Ntlm(nc);
            string msg = ntlm.CreateNegotiateMessage(spnego: !useNtlm);

            var message = new HttpRequestMessage(HttpMethod.Get, uri);
            message.Headers.Add("Authorization", ntlm.CreateNegotiateMessage(spnego: !useNtlm));

            HttpResponseMessage response = await client.SendAsync(message, default);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
                {
                    string blob = ntlm.ProcessChallenge(header);
                    if (!string.IsNullOrEmpty(blob))
                    {
                        message = new HttpRequestMessage(HttpMethod.Get, uri);
                        message.Headers.Add("Authorization", blob);
                        response = await client.SendAsync(message, default);
                    }
                }
            }

            Console.WriteLine(response);
        }

        static async Task Main(string[] args)
        {
            string uri = args.Length > 0 ? args[0] : "http://github.com/";
            string env = Environment.GetEnvironmentVariable("CREDENTIALS");

            if (String.IsNullOrEmpty(env))
            {
                // lame credentials. cab be updated for testing.
                nc = new NetworkCredential("test", "????", "");
            }
            else
            {
                // assume domain\user:password
                string[] part1 = env.Split(new char[] { ':' } , 2);
                string[] part2 = part1[0].Split(new char[] { '\\' }, 2);
                if (part2.Length == 1)
                {
                    nc = new NetworkCredential(part1[0], part1[1]);
                }
                else
                {
                    nc = new NetworkCredential(part2[1], part1[1], part2[0]);
                }
            }

            var client = new HttpClient();
            HttpResponseMessage probe = await client.GetAsync(uri, CancellationToken.None);

            if (probe.StatusCode == HttpStatusCode.Unauthorized)
            {
                bool canDoNtlm = false;
                bool canDoNegotiate = false;

                foreach (AuthenticationHeaderValue header in probe.Headers.WwwAuthenticate)
                {
                    if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "NTLM"))
                    {
                        canDoNtlm = true;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "Negotiate"))
                    {
                        canDoNegotiate = true;
                    }
                    else
                    {
                        Console.WriteLine($"{uri} offers {header.Scheme} authentication");
                    }
                }

                Console.WriteLine("{0} {1} do NTLM authentication", uri, canDoNtlm ? "can" : "cannot");
                Console.WriteLine("{0} {1} do Negotiate authentication", uri, canDoNegotiate? "can" : "cannot");

                if (canDoNtlm)
                {
                    try
                    {
                        await Authenticate(uri, true);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("NTLM Authentication failed");
                        Console.WriteLine(ex);
                    }
                }

                if (canDoNegotiate)
                {
                    try
                    {
                        await Authenticate(uri, false);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Negotiate Authentication failed");
                        Console.WriteLine(ex);
                    }
                }
            }
            else
            {
                Console.WriteLine($"{uri} did not ask for authentication.");
                Console.WriteLine(probe);
            }
        }
    }
}
