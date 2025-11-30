using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Usenet.Nntp
{
    public static class CustomCertValidator
    {
        private static readonly HashSet<string> IgnoredHosts =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static bool _ignoreAllNameMismatch = false;

        // --------------------------------------------------------
        // Static constructor: reads environment variables once
        // --------------------------------------------------------
        static CustomCertValidator()
        {
            // Global ignore flag
            var ignoreAll = Environment.GetEnvironmentVariable("NZBDAV_NNTP_TLS_IGNORE_NAME_MISMATCH");
            if (!string.IsNullOrEmpty(ignoreAll) &&
                ignoreAll.Equals("true", StringComparison.OrdinalIgnoreCase))
            {
                EnableGlobalIgnore();
            }

            // Per-host ignore list
            var hosts = Environment.GetEnvironmentVariable("NZBDAV_NNTP_TLS_IGNORE_HOSTS");
            if (!string.IsNullOrWhiteSpace(hosts))
            {
                foreach (var host in hosts.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    AddIgnoredHost(host.Trim());
                }
            }
        }

        /// <summary>
        /// Globally ignore RemoteCertificateNameMismatch for all hosts.
        /// </summary>
        public static void EnableGlobalIgnore()
        {
            _ignoreAllNameMismatch = true;
        }

        /// <summary>
        /// Ignore certificate name mismatch for a specific hostname.
        /// </summary>
        public static void AddIgnoredHost(string host)
        {
            if (!string.IsNullOrWhiteSpace(host))
                IgnoredHosts.Add(host);
        }

        /// <summary>
        /// Validate the server certificate, applying global and per-host overrides.
        /// </summary>
        public static bool Validate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslErrors,
            string targetHost)
        {
            // Allow all mismatched certs globally
            if (_ignoreAllNameMismatch &&
                sslErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                return true;

            // Allow mismatched certs for specific hosts
            if (IgnoredHosts.Contains(targetHost) &&
                sslErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                return true;

            // Allow only completely clean certificates otherwise
            return sslErrors == SslPolicyErrors.None;
        }
    }
}
