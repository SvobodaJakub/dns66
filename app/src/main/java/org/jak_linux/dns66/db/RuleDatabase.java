/* Copyright (C) 2016 - 2017 Julian Andres Klode <jak@jak-linux.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package org.jak_linux.dns66.db;

import android.content.Context;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Log;

import org.jak_linux.dns66.Configuration;
import org.jak_linux.dns66.FileHelper;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashSet;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents hosts that are blocked.
 * <p>
 * This is a very basic set of hosts. But it supports lock-free
 * readers with writers active at the same time, only the writers
 * having to take a lock.
 */
public class RuleDatabase {

    private static final String TAG = "RuleDatabase";
    private static final RuleDatabase instance = new RuleDatabase();
    final AtomicReference<HashSet<String>> blockedHosts = new AtomicReference<>(new HashSet<String>());
    HashSet<String> nextBlockedHosts = null;
    Configuration config = null;

    /**
     * Package-private constructor for instance and unit tests.
     */
    RuleDatabase() {

    }


    /**
     * Returns the instance of the rule database.
     */
    public static RuleDatabase getInstance() {
        return instance;
    }

    /**
     * Parse a single line in a hosts file
     *
     * @param line A line to parse
     * @return A host
     */
    @Nullable
    static String parseLine(String line) {

        //TODO rework logic so that it uses only indexes and charAt; no splitting etc
        //TODO add input for setting of how deep similar domains are merged

        // Reject AdBlock Plus filters like these
        // www.google.com#@##videoads
        // because otherwise, the filter exception (#@##videoads) would be treated as a comment
        // and then www.google.com would be treated as a domain (presumably to block)
        if (line.contains("#@#"))
            return null;

        int endOfLine = line.indexOf('#');

        if (endOfLine == -1)
            endOfLine = line.length();

        // Trim spaces
        while (endOfLine > 0 && Character.isWhitespace(line.charAt(endOfLine - 1)))
            endOfLine--;

        // The line is empty.
        if (endOfLine <= 0)
            return null;

        // Find beginning of host field
        int startOfHost = 0;

        if (line.regionMatches(0, "127.0.0.1", 0, 9) && (endOfLine <= 9 || Character.isWhitespace(line.charAt(9))))
            startOfHost += 10;
        else if (line.regionMatches(0, "::1", 0, 3) && (endOfLine <= 3 || Character.isWhitespace(line.charAt(3))))
            startOfHost += 4;
        else if (line.regionMatches(0, "0.0.0.0", 0, 7) && (endOfLine <= 7 || Character.isWhitespace(line.charAt(7))))
            startOfHost += 8;

        // Trim of space at the beginning of the host.
        while (startOfHost < endOfLine && Character.isWhitespace(line.charAt(startOfHost)))
            startOfHost++;

        // If the host is ||domain^, strip the || and ^ - AdBlock Plus syntax for whole domains
        if ((line.charAt(endOfLine - 1) == '^') && (
                (line.charAt(startOfHost) == '|') && (line.charAt(startOfHost + 1) == '|')
        )) {
            startOfHost += 2;
            endOfLine--;
        }

        // Reject strings containing a space or one of the symbols - that wouldn't be a signle
        // domain but some more complicated AdBlock plus filter and we want to ignore them
        for (int i = startOfHost; i < endOfLine; i++) {
            if (Character.isWhitespace(line.charAt(i)))
                return null;
            if (line.charAt(i) == '#')
                return null;
            if (line.charAt(i) == '/')
                return null;
            if (line.charAt(i) == '?')
                return null;
            if (line.charAt(i) == ',')
                return null;
            if (line.charAt(i) == ';')
                return null;
            if (line.charAt(i) == ':')
                return null;
            if (line.charAt(i) == '!')
                return null;
            if (line.charAt(i) == '|')
                return null;
            if (line.charAt(i) == '[')
                return null;
            if (line.charAt(i) == '&')
                return null;
            if (line.charAt(i) == '$')
                return null;
            if (line.charAt(i) == '@')
                return null;
            if (line.charAt(i) == '=')
                return null;
            if (line.charAt(i) == '^')
                return null;
            if (line.charAt(i) == '+')
                return null;
        }

        // Reject strings beginning with either of these chars:
        // .  , ; ?  !  : - | / [ & $ @ _ = ^ + #
        // (at this point, domains of format ||domain^ were already detected)
        // these are control chars of the AdBlock Plus format and we want to ignore such lines
        if (line.charAt(startOfHost) == '.') return null;
        if (line.charAt(startOfHost) == '-') return null;
        if (line.charAt(startOfHost) == '_') return null;

        // already detected - if (line.charAt(startOfHost) == ',') return null;
        // already detected - if (line.charAt(startOfHost) == ';') return null;
        // already detected - if (line.charAt(startOfHost) == '?') return null;
        // already detected - if (line.charAt(startOfHost) == '!') return null;
        // already detected - if (line.charAt(startOfHost) == ':') return null;
        // already detected - if (line.charAt(startOfHost) == '|') return null;
        // already detected - if (line.charAt(startOfHost) == '/') return null;
        // already detected - if (line.charAt(startOfHost) == '[') return null;
        // already detected - if (line.charAt(startOfHost) == '&') return null;
        // already detected - if (line.charAt(startOfHost) == '$') return null;
        // already detected - if (line.charAt(startOfHost) == '@') return null;
        // already detected - if (line.charAt(startOfHost) == '=') return null;
        // already detected - if (line.charAt(startOfHost) == '^') return null;
        // already detected - if (line.charAt(startOfHost) == '+') return null;
        // already detected - if (line.charAt(startOfHost) == '#') return null;

        // Also reject strings ending with those chars
        if (line.charAt(endOfLine - 1) == '.') return null;
        if (line.charAt(endOfLine - 1) == '-') return null;
        if (line.charAt(endOfLine - 1) == '_') return null;

        if (startOfHost >= endOfLine)
            return null;

        // reject if there is no dot in the string
        int numOfDots = 0;
        for (int i = startOfHost; i < endOfLine; i++) {
            if (line.charAt(i) == '.')
                numOfDots++;
        }
        if (numOfDots == 0)
                return null;

        // reject strings shorter than 3 characters
        if (startOfHost + 2 >= (endOfLine - 1) )
            return null;

        return line.substring(startOfHost, endOfLine).toLowerCase(Locale.ENGLISH);
    }

    /**
     * Checks if a host is blocked.
     *
     * @param host A hostname
     * @return true if the host is blocked, false otherwise.
     */
    public boolean isBlocked(String host) {

        // example: host == server3389.de.beacon.tracking.badserver.com
        if (blockedHosts.get().contains(host)) {
            return true;
        }

        if ((null != config) && (config.extendedFiltering.enabled)) {
            // example of chopping off:
            // i == 0, host == de.beacon.tracking.badserver.com
            // i == 1, host == beacon.tracking.badserver.com
            // i == 2, host == tracking.badserver.com
            // i == 3, host == badserver.com
            // i == 4, host == com
            // (yes, comparing even the top-level domain so that malicious TLDs can be present in the
            //  blocklist and can be blocked)

            // This is effectively like having a wildcard before every domain in the blacklist -
            // *.example.com

            for (int i = 0; i < 10; i++) {
                // strip up to 10 leading parts (so that there is an upper bound for performance reasons)
                String[] split_host = host.split("\\.", 2);
                if (split_host.length <= 1) {
                    // there's nothing to chop off left
                    break;
                }
                host = split_host[1];
                if (blockedHosts.get().contains(host)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if any hosts are blocked
     *
     * @return true if any hosts are blocked, false otherwise.
     */
    boolean isEmpty() {
        return blockedHosts.get().isEmpty();
    }

    /**
     * Load the hosts according to the configuration
     *
     * @param context A context used for opening files.
     * @throws InterruptedException Thrown if the thread was interrupted, so we don't waste time
     *                              reading more host files than needed.
     */
    public synchronized void initialize(Context context) throws InterruptedException {
        config = FileHelper.loadCurrentSettings(context);

        nextBlockedHosts = new HashSet<>(blockedHosts.get().size());

        Log.i(TAG, "Loading block list");

        if (!config.hosts.enabled) {
            Log.d(TAG, "loadBlockedHosts: Not loading, disabled.");
        } else {
            for (Configuration.Item item : config.hosts.items) {
                if (Thread.interrupted())
                    throw new InterruptedException("Interrupted");
                loadItem(context, item);
            }
        }

        blockedHosts.set(nextBlockedHosts);
        Runtime.getRuntime().gc();
    }

    /**
     * Loads an item. An item can be backed by a file or contain a value in the location field.
     *
     * @param context Context to open files
     * @param item    The item to load.
     * @throws InterruptedException If the thread was interrupted.
     */
    private void loadItem(Context context, Configuration.Item item) throws InterruptedException {
        if (item.state == Configuration.Item.STATE_IGNORE)
            return;

        InputStreamReader reader;
        try {
            reader = FileHelper.openItemFile(context, item);
        } catch (FileNotFoundException e) {
            Log.d(TAG, "loadItem: File not found: " + item.location);
            return;
        }

        if (reader == null) {
            addHost(item, item.location);
            return;
        } else {
            loadReader(item, reader);
        }
    }

    /**
     * Add a host for an item.
     * If the host address has more than 3 parts (e.g. en.analytics.example.com), it also adds
     * the last 3 parts as another host (e.g. analytics.example.com), so that related subdomains
     * are handled as well (e.g. de.analytics.example.com). This cannot be done for two parts
     * because e.g. analytics.example.com would cause example.com and docs.example.com to be
     * blocked as well and we don't want that. 3 parts is the best balance.
     * If the public suffix is something else than one part (e.g. co.uk instead of com),
     * it is adjusted accordingly.
     * If the host address begins with "www." (e.g. www.badsite.com), it also adds the domain
     * name without the leading "www." (e.g. badsite.com).
     *
     * @param item The item the host belongs to
     * @param host The host
     */
    private void addHost(Configuration.Item item, String host) {

        addHostSingle(item, host);

        if ((null != config) && (config.extendedFiltering.enabled)) {
            //TODO rework logic so that it uses only indexes and charAt; no splitting etc

            String[] split_host = host.split("\\.");
            if (split_host.length > 3) {  // optimization - with less than 3, it doesn't matter
                // If the host address has more than 3 parts (e.g. en.analytics.example.com), it also adds
                // the last 3 parts as another host (e.g. analytics.example.com), so that related subdomains
                // are handled as well (e.g. de.analytics.example.com). This cannot be done for two parts
                // because e.g. analytics.example.com would cause example.com and docs.example.com to be
                // blocked as well and we don't want that. 3 parts is the best balance.
                // If the public suffix is something else than one part (e.g. co.uk instead of com),
                // it is adjusted accordingly.
                int partsPublicSuffix = howManyPartsIsPublicSuffix(host);
                int resultPartsNum = 2 + partsPublicSuffix;

                if (split_host.length > resultPartsNum) {
                    String[] split_host_2 = new String[resultPartsNum];
                    System.arraycopy(split_host, split_host.length - resultPartsNum, split_host_2, 0, resultPartsNum);
                    String host_2 = TextUtils.join(".", split_host_2);
                    addHostSingle(item, host_2);
                }
            }

            // TODO move this to the parsing function
            // If the host address begins with "www." (e.g. www.badsite.com), it also adds the domain
            // name without the leading "www." (e.g. badsite.com).
            String[] split_host_3 = host.split("\\.", 2);
            if (split_host_3.length == 2) {
                if (split_host_3[0].equals("www")) {
                    addHostSingle(item, split_host_3[1]);
                }
            }
        }
    }

    /**
     * Add a single host for an item. No host name mangling.
     *
     * @param item The item the host belongs to
     * @param host The host
     */
    private void addHostSingle(Configuration.Item item, String host) {
        // Single address to block
        if (item.state == Configuration.Item.STATE_ALLOW) {
            nextBlockedHosts.remove(host);
        } else if (item.state == Configuration.Item.STATE_DENY) {
            nextBlockedHosts.add(host);
        }
    }

    /**
     * Load a single file
     *
     * @param item   The configuration item referencing the file
     * @param reader A reader to read lines from
     * @throws InterruptedException If thread was interrupted
     */
    boolean loadReader(Configuration.Item item, Reader reader) throws InterruptedException {
        int count = 0;
        try {
            Log.d(TAG, "loadBlockedHosts: Reading: " + item.location);
            try (BufferedReader br = new BufferedReader(reader)) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (Thread.interrupted())
                        throw new InterruptedException("Interrupted");
                    String host = parseLine(line);
                    if (host != null) {
                        count += 1;
                        addHost(item, host);
                    }
                }
            }
            Log.d(TAG, "loadBlockedHosts: Loaded " + count + " hosts from " + item.location);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "loadBlockedHosts: Error while reading " + item.location + " after " + count + " items", e);
            return false;
        } finally {
            FileHelper.closeOrWarn(reader, TAG, "loadBlockedHosts: Error closing " + item.location);
        }
    }

    /**
     * Returns number of parts (those strings in domain names joined by dots) of the public suffix
     * of the given domain name.
     * @param domain
     * @return Number of parts of the public suffix
     */
    protected int howManyPartsIsPublicSuffix(String domain) {
        String dotSuffix = getPublicSuffixWithDot(domain);
        if (dotSuffix == null) {
            return 1;
        } else {
            String[] split_suffix = dotSuffix.split("\\.");
            return split_suffix.length;
        }
    }

    /**
     * If the provided string ends with a public suffix that contains a dot, it returns the suffix.
     * Otherwise it returns null
     * @param s Domain tested for a public suffix
     * @return Suffix with dot or null
     */
    protected String getPublicSuffixWithDot(String s) {
        //TODO: most probably, this should be punycode and not unicode
        //TODO rework logic so that it uses only indexes and charAt; no splitting etc
        //TODO: use a simple algorithm instead of publicsuffix list - https://bugzilla.mozilla.org/show_bug.cgi?id=252342

        if (s.endsWith(".ltd.co.im")) {return "ltd.co.im";}
        if (s.endsWith(".plc.co.im")) {return "plc.co.im";}
        if (s.endsWith(".ac.uk")) {return "ac.uk";}
        if (s.endsWith(".co.uk")) {return "co.uk";}
        if (s.endsWith(".gov.uk")) {return "gov.uk";}
        if (s.endsWith(".ltd.uk")) {return "ltd.uk";}
        if (s.endsWith(".me.uk")) {return "me.uk";}
        if (s.endsWith(".net.uk")) {return "net.uk";}
        if (s.endsWith(".nhs.uk")) {return "nhs.uk";}
        if (s.endsWith(".org.uk")) {return "org.uk";}
        if (s.endsWith(".plc.uk")) {return "plc.uk";}
        if (s.endsWith(".police.uk")) {return "police.uk";}
        if (s.endsWith(".dni.us")) {return "dni.us";}
        if (s.endsWith(".fed.us")) {return "fed.us";}
        if (s.endsWith(".isa.us")) {return "isa.us";}
        if (s.endsWith(".kids.us")) {return "kids.us";}
        if (s.endsWith(".nsn.us")) {return "nsn.us";}
        if (s.endsWith(".ak.us")) {return "ak.us";}
        if (s.endsWith(".al.us")) {return "al.us";}
        if (s.endsWith(".ar.us")) {return "ar.us";}
        if (s.endsWith(".as.us")) {return "as.us";}
        if (s.endsWith(".az.us")) {return "az.us";}
        if (s.endsWith(".ca.us")) {return "ca.us";}
        if (s.endsWith(".co.us")) {return "co.us";}
        if (s.endsWith(".ct.us")) {return "ct.us";}
        if (s.endsWith(".dc.us")) {return "dc.us";}
        if (s.endsWith(".de.us")) {return "de.us";}
        if (s.endsWith(".fl.us")) {return "fl.us";}
        if (s.endsWith(".ga.us")) {return "ga.us";}
        if (s.endsWith(".gu.us")) {return "gu.us";}
        if (s.endsWith(".hi.us")) {return "hi.us";}
        if (s.endsWith(".ia.us")) {return "ia.us";}
        if (s.endsWith(".id.us")) {return "id.us";}
        if (s.endsWith(".il.us")) {return "il.us";}
        if (s.endsWith(".in.us")) {return "in.us";}
        if (s.endsWith(".ks.us")) {return "ks.us";}
        if (s.endsWith(".ky.us")) {return "ky.us";}
        if (s.endsWith(".la.us")) {return "la.us";}
        if (s.endsWith(".ma.us")) {return "ma.us";}
        if (s.endsWith(".md.us")) {return "md.us";}
        if (s.endsWith(".me.us")) {return "me.us";}
        if (s.endsWith(".mi.us")) {return "mi.us";}
        if (s.endsWith(".mn.us")) {return "mn.us";}
        if (s.endsWith(".mo.us")) {return "mo.us";}
        if (s.endsWith(".ms.us")) {return "ms.us";}
        if (s.endsWith(".mt.us")) {return "mt.us";}
        if (s.endsWith(".nc.us")) {return "nc.us";}
        if (s.endsWith(".nd.us")) {return "nd.us";}
        if (s.endsWith(".ne.us")) {return "ne.us";}
        if (s.endsWith(".nh.us")) {return "nh.us";}
        if (s.endsWith(".nj.us")) {return "nj.us";}
        if (s.endsWith(".nm.us")) {return "nm.us";}
        if (s.endsWith(".nv.us")) {return "nv.us";}
        if (s.endsWith(".ny.us")) {return "ny.us";}
        if (s.endsWith(".oh.us")) {return "oh.us";}
        if (s.endsWith(".ok.us")) {return "ok.us";}
        if (s.endsWith(".or.us")) {return "or.us";}
        if (s.endsWith(".pa.us")) {return "pa.us";}
        if (s.endsWith(".pr.us")) {return "pr.us";}
        if (s.endsWith(".ri.us")) {return "ri.us";}
        if (s.endsWith(".sc.us")) {return "sc.us";}
        if (s.endsWith(".sd.us")) {return "sd.us";}
        if (s.endsWith(".tn.us")) {return "tn.us";}
        if (s.endsWith(".tx.us")) {return "tx.us";}
        if (s.endsWith(".ut.us")) {return "ut.us";}
        if (s.endsWith(".vi.us")) {return "vi.us";}
        if (s.endsWith(".vt.us")) {return "vt.us";}
        if (s.endsWith(".va.us")) {return "va.us";}
        if (s.endsWith(".wa.us")) {return "wa.us";}
        if (s.endsWith(".wi.us")) {return "wi.us";}
        if (s.endsWith(".wv.us")) {return "wv.us";}
        if (s.endsWith(".wy.us")) {return "wy.us";}
        if (s.endsWith(".k12.ak.us")) {return "k12.ak.us";}
        if (s.endsWith(".k12.al.us")) {return "k12.al.us";}
        if (s.endsWith(".k12.ar.us")) {return "k12.ar.us";}
        if (s.endsWith(".k12.as.us")) {return "k12.as.us";}
        if (s.endsWith(".k12.az.us")) {return "k12.az.us";}
        if (s.endsWith(".k12.ca.us")) {return "k12.ca.us";}
        if (s.endsWith(".k12.co.us")) {return "k12.co.us";}
        if (s.endsWith(".k12.ct.us")) {return "k12.ct.us";}
        if (s.endsWith(".k12.dc.us")) {return "k12.dc.us";}
        if (s.endsWith(".k12.de.us")) {return "k12.de.us";}
        if (s.endsWith(".k12.fl.us")) {return "k12.fl.us";}
        if (s.endsWith(".k12.ga.us")) {return "k12.ga.us";}
        if (s.endsWith(".k12.gu.us")) {return "k12.gu.us";}
        if (s.endsWith(".k12.ia.us")) {return "k12.ia.us";}
        if (s.endsWith(".k12.id.us")) {return "k12.id.us";}
        if (s.endsWith(".k12.il.us")) {return "k12.il.us";}
        if (s.endsWith(".k12.in.us")) {return "k12.in.us";}
        if (s.endsWith(".k12.ks.us")) {return "k12.ks.us";}
        if (s.endsWith(".k12.ky.us")) {return "k12.ky.us";}
        if (s.endsWith(".k12.la.us")) {return "k12.la.us";}
        if (s.endsWith(".k12.ma.us")) {return "k12.ma.us";}
        if (s.endsWith(".k12.md.us")) {return "k12.md.us";}
        if (s.endsWith(".k12.me.us")) {return "k12.me.us";}
        if (s.endsWith(".k12.mn.us")) {return "k12.mn.us";}
        if (s.endsWith(".k12.mo.us")) {return "k12.mo.us";}
        if (s.endsWith(".k12.ms.us")) {return "k12.ms.us";}
        if (s.endsWith(".k12.mt.us")) {return "k12.mt.us";}
        if (s.endsWith(".k12.nc.us")) {return "k12.nc.us";}
        if (s.endsWith(".k12.ne.us")) {return "k12.ne.us";}
        if (s.endsWith(".k12.nh.us")) {return "k12.nh.us";}
        if (s.endsWith(".k12.nj.us")) {return "k12.nj.us";}
        if (s.endsWith(".k12.nm.us")) {return "k12.nm.us";}
        if (s.endsWith(".k12.nv.us")) {return "k12.nv.us";}
        if (s.endsWith(".k12.ny.us")) {return "k12.ny.us";}
        if (s.endsWith(".k12.oh.us")) {return "k12.oh.us";}
        if (s.endsWith(".k12.ok.us")) {return "k12.ok.us";}
        if (s.endsWith(".k12.or.us")) {return "k12.or.us";}
        if (s.endsWith(".k12.pa.us")) {return "k12.pa.us";}
        if (s.endsWith(".k12.pr.us")) {return "k12.pr.us";}
        if (s.endsWith(".k12.ri.us")) {return "k12.ri.us";}
        if (s.endsWith(".k12.sc.us")) {return "k12.sc.us";}
        if (s.endsWith(".k12.tn.us")) {return "k12.tn.us";}
        if (s.endsWith(".k12.tx.us")) {return "k12.tx.us";}
        if (s.endsWith(".k12.ut.us")) {return "k12.ut.us";}
        if (s.endsWith(".k12.vi.us")) {return "k12.vi.us";}
        if (s.endsWith(".k12.vt.us")) {return "k12.vt.us";}
        if (s.endsWith(".k12.va.us")) {return "k12.va.us";}
        if (s.endsWith(".k12.wa.us")) {return "k12.wa.us";}
        if (s.endsWith(".k12.wi.us")) {return "k12.wi.us";}
        if (s.endsWith(".k12.wy.us")) {return "k12.wy.us";}
        if (s.endsWith(".cc.ak.us")) {return "cc.ak.us";}
        if (s.endsWith(".cc.al.us")) {return "cc.al.us";}
        if (s.endsWith(".cc.ar.us")) {return "cc.ar.us";}
        if (s.endsWith(".cc.as.us")) {return "cc.as.us";}
        if (s.endsWith(".cc.az.us")) {return "cc.az.us";}
        if (s.endsWith(".cc.ca.us")) {return "cc.ca.us";}
        if (s.endsWith(".cc.co.us")) {return "cc.co.us";}
        if (s.endsWith(".cc.ct.us")) {return "cc.ct.us";}
        if (s.endsWith(".cc.dc.us")) {return "cc.dc.us";}
        if (s.endsWith(".cc.de.us")) {return "cc.de.us";}
        if (s.endsWith(".cc.fl.us")) {return "cc.fl.us";}
        if (s.endsWith(".cc.ga.us")) {return "cc.ga.us";}
        if (s.endsWith(".cc.gu.us")) {return "cc.gu.us";}
        if (s.endsWith(".cc.hi.us")) {return "cc.hi.us";}
        if (s.endsWith(".cc.ia.us")) {return "cc.ia.us";}
        if (s.endsWith(".cc.id.us")) {return "cc.id.us";}
        if (s.endsWith(".cc.il.us")) {return "cc.il.us";}
        if (s.endsWith(".cc.in.us")) {return "cc.in.us";}
        if (s.endsWith(".cc.ks.us")) {return "cc.ks.us";}
        if (s.endsWith(".cc.ky.us")) {return "cc.ky.us";}
        if (s.endsWith(".cc.la.us")) {return "cc.la.us";}
        if (s.endsWith(".cc.ma.us")) {return "cc.ma.us";}
        if (s.endsWith(".cc.md.us")) {return "cc.md.us";}
        if (s.endsWith(".cc.me.us")) {return "cc.me.us";}
        if (s.endsWith(".cc.mn.us")) {return "cc.mn.us";}
        if (s.endsWith(".cc.mo.us")) {return "cc.mo.us";}
        if (s.endsWith(".cc.ms.us")) {return "cc.ms.us";}
        if (s.endsWith(".cc.mt.us")) {return "cc.mt.us";}
        if (s.endsWith(".cc.nc.us")) {return "cc.nc.us";}
        if (s.endsWith(".cc.nd.us")) {return "cc.nd.us";}
        if (s.endsWith(".cc.ne.us")) {return "cc.ne.us";}
        if (s.endsWith(".cc.nh.us")) {return "cc.nh.us";}
        if (s.endsWith(".cc.nj.us")) {return "cc.nj.us";}
        if (s.endsWith(".cc.nm.us")) {return "cc.nm.us";}
        if (s.endsWith(".cc.nv.us")) {return "cc.nv.us";}
        if (s.endsWith(".cc.ny.us")) {return "cc.ny.us";}
        if (s.endsWith(".cc.oh.us")) {return "cc.oh.us";}
        if (s.endsWith(".cc.ok.us")) {return "cc.ok.us";}
        if (s.endsWith(".cc.or.us")) {return "cc.or.us";}
        if (s.endsWith(".cc.pa.us")) {return "cc.pa.us";}
        if (s.endsWith(".cc.pr.us")) {return "cc.pr.us";}
        if (s.endsWith(".cc.ri.us")) {return "cc.ri.us";}
        if (s.endsWith(".cc.sc.us")) {return "cc.sc.us";}
        if (s.endsWith(".cc.sd.us")) {return "cc.sd.us";}
        if (s.endsWith(".cc.tn.us")) {return "cc.tn.us";}
        if (s.endsWith(".cc.tx.us")) {return "cc.tx.us";}
        if (s.endsWith(".cc.ut.us")) {return "cc.ut.us";}
        if (s.endsWith(".cc.vi.us")) {return "cc.vi.us";}
        if (s.endsWith(".cc.vt.us")) {return "cc.vt.us";}
        if (s.endsWith(".cc.va.us")) {return "cc.va.us";}
        if (s.endsWith(".cc.wa.us")) {return "cc.wa.us";}
        if (s.endsWith(".cc.wi.us")) {return "cc.wi.us";}
        if (s.endsWith(".cc.wv.us")) {return "cc.wv.us";}
        if (s.endsWith(".cc.wy.us")) {return "cc.wy.us";}
        if (s.endsWith(".lib.ak.us")) {return "lib.ak.us";}
        if (s.endsWith(".lib.al.us")) {return "lib.al.us";}
        if (s.endsWith(".lib.ar.us")) {return "lib.ar.us";}
        if (s.endsWith(".lib.as.us")) {return "lib.as.us";}
        if (s.endsWith(".lib.az.us")) {return "lib.az.us";}
        if (s.endsWith(".lib.ca.us")) {return "lib.ca.us";}
        if (s.endsWith(".lib.co.us")) {return "lib.co.us";}
        if (s.endsWith(".lib.ct.us")) {return "lib.ct.us";}
        if (s.endsWith(".lib.dc.us")) {return "lib.dc.us";}
        if (s.endsWith(".lib.fl.us")) {return "lib.fl.us";}
        if (s.endsWith(".lib.ga.us")) {return "lib.ga.us";}
        if (s.endsWith(".lib.gu.us")) {return "lib.gu.us";}
        if (s.endsWith(".lib.hi.us")) {return "lib.hi.us";}
        if (s.endsWith(".lib.ia.us")) {return "lib.ia.us";}
        if (s.endsWith(".lib.id.us")) {return "lib.id.us";}
        if (s.endsWith(".lib.il.us")) {return "lib.il.us";}
        if (s.endsWith(".lib.in.us")) {return "lib.in.us";}
        if (s.endsWith(".lib.ks.us")) {return "lib.ks.us";}
        if (s.endsWith(".lib.ky.us")) {return "lib.ky.us";}
        if (s.endsWith(".lib.la.us")) {return "lib.la.us";}
        if (s.endsWith(".lib.ma.us")) {return "lib.ma.us";}
        if (s.endsWith(".lib.md.us")) {return "lib.md.us";}
        if (s.endsWith(".lib.me.us")) {return "lib.me.us";}
        if (s.endsWith(".lib.mn.us")) {return "lib.mn.us";}
        if (s.endsWith(".lib.mo.us")) {return "lib.mo.us";}
        if (s.endsWith(".lib.ms.us")) {return "lib.ms.us";}
        if (s.endsWith(".lib.mt.us")) {return "lib.mt.us";}
        if (s.endsWith(".lib.nc.us")) {return "lib.nc.us";}
        if (s.endsWith(".lib.nd.us")) {return "lib.nd.us";}
        if (s.endsWith(".lib.ne.us")) {return "lib.ne.us";}
        if (s.endsWith(".lib.nh.us")) {return "lib.nh.us";}
        if (s.endsWith(".lib.nj.us")) {return "lib.nj.us";}
        if (s.endsWith(".lib.nm.us")) {return "lib.nm.us";}
        if (s.endsWith(".lib.nv.us")) {return "lib.nv.us";}
        if (s.endsWith(".lib.ny.us")) {return "lib.ny.us";}
        if (s.endsWith(".lib.oh.us")) {return "lib.oh.us";}
        if (s.endsWith(".lib.ok.us")) {return "lib.ok.us";}
        if (s.endsWith(".lib.or.us")) {return "lib.or.us";}
        if (s.endsWith(".lib.pa.us")) {return "lib.pa.us";}
        if (s.endsWith(".lib.pr.us")) {return "lib.pr.us";}
        if (s.endsWith(".lib.ri.us")) {return "lib.ri.us";}
        if (s.endsWith(".lib.sc.us")) {return "lib.sc.us";}
        if (s.endsWith(".lib.sd.us")) {return "lib.sd.us";}
        if (s.endsWith(".lib.tn.us")) {return "lib.tn.us";}
        if (s.endsWith(".lib.tx.us")) {return "lib.tx.us";}
        if (s.endsWith(".lib.ut.us")) {return "lib.ut.us";}
        if (s.endsWith(".lib.vi.us")) {return "lib.vi.us";}
        if (s.endsWith(".lib.vt.us")) {return "lib.vt.us";}
        if (s.endsWith(".lib.va.us")) {return "lib.va.us";}
        if (s.endsWith(".lib.wa.us")) {return "lib.wa.us";}
        if (s.endsWith(".lib.wi.us")) {return "lib.wi.us";}
        if (s.endsWith(".lib.wy.us")) {return "lib.wy.us";}
        if (s.endsWith(".pvt.k12.ma.us")) {return "pvt.k12.ma.us";}
        if (s.endsWith(".chtr.k12.ma.us")) {return "chtr.k12.ma.us";}
        if (s.endsWith(".paroch.k12.ma.us")) {return "paroch.k12.ma.us";}
        if (s.endsWith(".ar.com")) {return "ar.com";}
        if (s.endsWith(".br.com")) {return "br.com";}
        if (s.endsWith(".cn.com")) {return "cn.com";}
        if (s.endsWith(".de.com")) {return "de.com";}
        if (s.endsWith(".eu.com")) {return "eu.com";}
        if (s.endsWith(".gb.com")) {return "gb.com";}
        if (s.endsWith(".hu.com")) {return "hu.com";}
        if (s.endsWith(".jpn.com")) {return "jpn.com";}
        if (s.endsWith(".kr.com")) {return "kr.com";}
        if (s.endsWith(".mex.com")) {return "mex.com";}
        if (s.endsWith(".no.com")) {return "no.com";}
        if (s.endsWith(".qc.com")) {return "qc.com";}
        if (s.endsWith(".ru.com")) {return "ru.com";}
        if (s.endsWith(".sa.com")) {return "sa.com";}
        if (s.endsWith(".se.com")) {return "se.com";}
        if (s.endsWith(".uk.com")) {return "uk.com";}
        if (s.endsWith(".us.com")) {return "us.com";}
        if (s.endsWith(".uy.com")) {return "uy.com";}
        if (s.endsWith(".za.com")) {return "za.com";}
        if (s.endsWith(".africa.com")) {return "africa.com";}
        if (s.endsWith(".gr.com")) {return "gr.com";}
        if (s.endsWith(".co.com")) {return "co.com";}
        if (s.endsWith(".xenapponazure.com")) {return "xenapponazure.com";}
        if (s.endsWith(".jdevcloud.com")) {return "jdevcloud.com";}
        if (s.endsWith(".wpdevcloud.com")) {return "wpdevcloud.com";}
        if (s.endsWith(".cloudcontrolled.com")) {return "cloudcontrolled.com";}
        if (s.endsWith(".cloudcontrolapp.com")) {return "cloudcontrolapp.com";}
        if (s.endsWith(".firebaseapp.com")) {return "firebaseapp.com";}
        if (s.endsWith(".service.gov.uk")) {return "service.gov.uk";}
        if (s.endsWith(".githubusercontent.com")) {return "githubusercontent.com";}
        if (s.endsWith(".homeoffice.gov.uk")) {return "homeoffice.gov.uk";}
        if (s.endsWith(".appspot.com")) {return "appspot.com";}
        if (s.endsWith(".codespot.com")) {return "codespot.com";}
        if (s.endsWith(".googleapis.com")) {return "googleapis.com";}
        if (s.endsWith(".googlecode.com")) {return "googlecode.com";}
        if (s.endsWith(".herokuapp.com")) {return "herokuapp.com";}
        if (s.endsWith(".herokussl.com")) {return "herokussl.com";}
        if (s.endsWith(".pixolino.com")) {return "pixolino.com";}
        if (s.endsWith(".barsyonline.com")) {return "barsyonline.com";}
        if (s.endsWith(".hk.com")) {return "hk.com";}


        return null;
    }


}
