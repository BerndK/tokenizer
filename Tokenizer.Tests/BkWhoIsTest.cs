using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Tokens
{
    public class BkWhoIsTest
    {
        private string Patterns = @"% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

domain:       #{WhoisServerRecord.TLD:ToLower()}

organisation: #{WhoisServerRecord.Organization.Name}
address:      #{WhoisServerRecord.Organization.Address}

contact:      administrative
name:         #{WhoisServerRecord.AdminContact.Name}
organisation: #{WhoisServerRecord.AdminContact.Organization}
address:      #{WhoisServerRecord.AdminContact.Address}
phone:        #{WhoisServerRecord.AdminContact.TelephoneNumber}
fax-no:       #{WhoisServerRecord.AdminContact.FaxNumber}
e-mail:       #{WhoisServerRecord.AdminContact.Email}

contact:      technical
name:         #{WhoisServerRecord.TechContact.Name}
organisation: #{WhoisServerRecord.TechContact.Organization}
address:      #{WhoisServerRecord.TechContact.Address}
phone:        #{WhoisServerRecord.TechContact.TelephoneNumber}
fax-no:       #{WhoisServerRecord.TechContact.FaxNumber}
e-mail:       #{WhoisServerRecord.TechContact.Email}

nserver:      #{WhoisServerRecord.NameServers}

whois:        #{WhoisServerRecord.Url}

status:       ACTIVE
remarks:      #{WhoisServerRecord.Remarks}

created:      #{WhoisServerRecord.Created}
changed:      #{WhoisServerRecord.Changed}
source:       IANA

";
        private string SimplePatterns = "whois:        #{WhoisServerRecord.Url}";

        private string Text = @"% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

refer:        whois.arin.net

inetnum:      216.0.0.0 - 216.255.255.255
organisation: ARIN
status:       ALLOCATED

whois:        whois.arin.net

changed:      1998-04
source:       IANA

";

#region TargetObjects
        /// <summary>
        /// Represents a contact who is responsible for administering a TLD
        /// </summary>
        public class Contact
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="Contact"/> class.
            /// </summary>
            public Contact()
            {
                Address = new List<string>();
            }

            /// <summary>
            /// Gets or sets the name.
            /// </summary>
            /// <value>
            /// The name.
            /// </value>
            public string Name { get; set; }

            /// <summary>
            /// Gets or sets the organization.
            /// </summary>
            /// <value>
            /// The organisation.
            /// </value>
            public string Organization { get; set; }

            /// <summary>
            /// Gets or sets the address.
            /// </summary>
            /// <value>
            /// The address.
            /// </value>
            public IList<string> Address { get; private set; }

            /// <summary>
            /// Gets or sets the telephone number.
            /// </summary>
            /// <value>
            /// The telephone number.
            /// </value>
            public string TelephoneNumber { get; set; }

            /// <summary>
            /// Gets or sets the fax number.
            /// </summary>
            /// <value>
            /// The fax number.
            /// </value>
            public string FaxNumber { get; set; }

            /// <summary>
            /// Gets or sets the email.
            /// </summary>
            /// <value>
            /// The email.
            /// </value>
            public string Email { get; set; }
        }

        /// <summary>
        /// Represents an Organization that is responsible for administering a TLD
        /// </summary>
        public class Organization
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="Organization"/> class.
            /// </summary>
            public Organization()
            {
                Address = new List<string>();
            }

            /// <summary>
            /// Gets or sets the name.
            /// </summary>
            /// <value>
            /// The name.
            /// </value>
            public string Name { get; set; }

            /// <summary>
            /// Gets or sets the address.
            /// </summary>
            /// <value>
            /// The address.
            /// </value>
            public IList<string> Address { get; set; }
        }

        /// <summary>
        /// Represents a WHOIS server for a TLD
        /// </summary>
        public class WhoisServerRecord //: IWhoisServer
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="WhoisServerRecord"/> class.
            /// </summary>
            public WhoisServerRecord()
            {
                NameServers = new List<string>();
            }

            /// <summary>
            /// Gets or sets the TLD.
            /// </summary>
            /// <value>
            /// The TLD.
            /// </value>
            public string TLD { get; set; }

            /// <summary>
            /// Gets or sets the URL of the WHOIS server for this TLD.
            /// </summary>
            /// <value>
            /// The URL.
            /// </value>
            public string Url { get; set; }

            /// <summary>
            /// Gets or sets the organization.
            /// </summary>
            /// <value>
            /// The organization.
            /// </value>
            public Organization Organization { get; set; }

            /// <summary>
            /// Gets or sets the admin contact.
            /// </summary>
            /// <value>
            /// The admin contact.
            /// </value>
            public Contact AdminContact { get; set; }

            /// <summary>
            /// Gets or sets the tech contact.
            /// </summary>
            /// <value>
            /// The tech contact.
            /// </value>
            public Contact TechContact { get; set; }

            /// <summary>
            /// Gets the name servers.
            /// </summary>
            /// <value>
            /// The name servers.
            /// </value>
            public IList<string> NameServers { get; private set; }

            /// <summary>
            /// Gets or sets any remarks about this TLD.
            /// </summary>
            /// <value>
            /// The remarks.
            /// </value>
            public string Remarks { get; set; }

            /// <summary>
            /// Gets or sets the created date.
            /// </summary>
            /// <value>
            /// The created.
            /// </value>
            public DateTime Created { get; set; }

            /// <summary>
            /// Gets or sets the change date.
            /// </summary>
            /// <value>
            /// The modified.
            /// </value>
            public DateTime Changed { get; set; }

            /// <summary>
            /// Gets or sets the raw response.
            /// </summary>
            /// <value>
            /// The raw response.
            /// </value>
            public string RawResponse { get; set; }
        }
#endregion

        [Test]
        public void TestWhoIs()
        {
            var tokenizer = new Tokenizer();
            var result = tokenizer.Parse<WhoisServerRecord>(Patterns, Text);
            Assert.AreNotEqual(result.Value.Url, null);
        }

        [Test]
        public void TestMultiLine()
        {
            var text = @"Domain name:
google.ch

Holder of domain name:
Google Inc.";
            var patterns = @"Domain name:
#{WhoisServerRecord.Url}

Holder of domain name:
#{WhoisServerRecord.Organization.Name}
";
            var tokenizer = new Tokenizer();
            var result = tokenizer.Parse<WhoisServerRecord>(patterns, text);
            Console.WriteLine($"org:{result.Value.Organization.Name}\r\nurl:{result.Value.Url}");
            Assert.AreNotEqual(result.Value.Url, null);
        }

    }
}
