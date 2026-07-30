<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:sitemap="http://www.sitemaps.org/schemas/sitemap/0.9">
<xsl:output method="html" encoding="UTF-8" indent="yes"/>
<xsl:template match="/">
<html lang="es">
<head>
    <meta charset="UTF-8"/>
    <title>Sitemap · Tiger DevLabs</title>
    <style>
        body {
            font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
            background: #07070b;
            color: #e9e9f1;
            margin: 0;
            padding: 40px;
        }
        h1 {
            color: #22d3ee;
            font-size: 20px;
            margin-bottom: 4px;
        }
        p.sub {
            color: #9ca3af;
            margin-top: 0;
            margin-bottom: 24px;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #0d0d16;
            border-radius: 12px;
            overflow: hidden;
        }
        th {
            text-align: left;
            background: #16161f;
            color: #c084fc;
            padding: 12px 16px;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        td {
            padding: 12px 16px;
            border-top: 1px solid #222;
            font-size: 14px;
        }
        a {
            color: #22d3ee;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>🐯 Sitemap de Tiger DevLabs</h1>
    <p class="sub"><xsl:value-of select="count(sitemap:urlset/sitemap:url)"/> URL(s) indexadas para motores de búsqueda.</p>
    <table>
        <tr>
            <th>URL</th>
            <th>Frecuencia de cambio</th>
            <th>Prioridad</th>
        </tr>
        <xsl:for-each select="sitemap:urlset/sitemap:url">
        <tr>
            <td><a href="{sitemap:loc}"><xsl:value-of select="sitemap:loc"/></a></td>
            <td><xsl:value-of select="sitemap:changefreq"/></td>
            <td><xsl:value-of select="sitemap:priority"/></td>
        </tr>
        </xsl:for-each>
    </table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
