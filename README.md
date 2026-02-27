<h1>zpe.lib.vault</h1>

<p>
  This is the official Vault plugin for ZPE.
</p>

<p>
  The plugin provides secure, encrypted and persistent storage for secrets such as API keys, passwords, tokens and credentials.
</p>

<h2>Installation</h2>

<p>
  Place <strong>zpe.lib.vault.jar</strong> in your ZPE native-plugins folder and restart ZPE.
</p>

<p>
  You can also download with the ZULE Package Manager by using:
</p>
<p>
  <code>zpe --zule install zpe.lib.vault.jar</code>
</p>

<h2>Documentation</h2>

<p>
  Full documentation, examples and API reference are available here:
</p>

<p>
  <a href="https://www.jamiebalfour.scot/projects/zpe/documentation/plugins/zpe.lib.vault/" target="_blank">
    View the complete documentation
  </a>
</p>

<h2>Example</h2>

<pre>

import "zpe.lib.vault"

vault = new Vault()

vault.init("my-secure-passphrase")

vault.set("octopus_api_key", "sk_live_123")
vault.set("smtp_password", "supersecret")

if (vault.has("smtp_password"))
    print(vault.get("smtp_password"))
end if

keys = vault.list_keys()

for (k in keys)
    print(k)
end for

vault.close()

</pre>

<h2>Notes</h2>

<ul>
  <li>Uses AES-GCM encryption for confidentiality and tamper protection.</li>
  <li>Keys are derived using PBKDF2 with a unique salt.</li>
  <li>Secrets are stored encrypted on disk.</li>
  <li>Cross-platform (Windows, macOS, Linux).</li>
  <li>Designed for secure use within the ZPE runtime environment.</li>
</ul>