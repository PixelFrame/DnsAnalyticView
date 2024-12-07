using Microsoft.Performance.SDK.Processing;
using System.Collections.Generic;
using System.Linq;

namespace DnsAnalyticView
{
    [ProcessingSource(
        "{AE28C036-46EC-4CD5-A19E-16239F6FEC9E}",
        "Windows DNS Server Analytical Log",
        "Microsoft-Windows-DNSServer/Analytical Events")]
    [FileDataSource(".etl", "ETL Files")]

    public class DnsAnalyticSource
        : ProcessingSource
    {
        private IApplicationEnvironment? applicationEnvironment;

        public override ProcessingSourceInfo GetAboutInfo()
        {
            return new ProcessingSourceInfo
            {
                CopyrightNotice = "Copyright 2024 KzA. All Rights Reserved.",
                LicenseInfo = new LicenseInfo
                {
                    Name = "MIT",
                    Text = "Please see the link for the full license text.",
                    Uri = "https://github.com/PixelFrame/DnsAnalyticView/blob/master/LICENSE.txt",
                },
                Owners = new[]
                {
                    new ContactInfo
                    {
                        Address = "N/A",
                        EmailAddresses = new[]
                        {
                            "pm421@live.com",
                        },
                    },
                },
                ProjectInfo = new ProjectInfo
                {
                    Uri = "https://github.com/PixelFrame/DnsAnalyticView",
                },
                AdditionalInformation = new[]
                {
                    "This Processing Source is used to process Microsoft-Windows-DNSServer/Analytical events",
                }
            };
        }

        protected override void SetApplicationEnvironmentCore(IApplicationEnvironment applicationEnvironment)
        {
            this.applicationEnvironment = applicationEnvironment;
        }

        protected override ICustomDataProcessor CreateProcessorCore(
            IEnumerable<IDataSource> dataSources,
            IProcessorEnvironment processorEnvironment,
            ProcessorOptions options)
        {
            return new DnsAnalyticDataProcessor(
                dataSources.Select(x => x.Uri.LocalPath).ToArray(),
                options,
                applicationEnvironment!,
                processorEnvironment);
        }

        protected override bool IsDataSourceSupportedCore(IDataSource source)
        {
            return true;
        }
    }
}
