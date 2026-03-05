import axios from 'axios';
import * as cheerio from 'cheerio';

/**
 * Dynamically extracts all 50 features from a live URL using axios and cheerio.
 */
export const extractFeaturesAsync = async (url: string) => {
  const features: any = {};
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith('http')) {
    cleanUrl = 'http://' + cleanUrl;
  }

  let urlObj;
  try {
    urlObj = new URL(cleanUrl);
  } catch (e) {
    urlObj = new URL('http://malformed.internal');
  }

  const hostname = urlObj.hostname;

  // Basic String Features
  features.URLLength = cleanUrl.length;
  features.DomainLength = hostname.length;
  features.IsDomainIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) ? 1 : 0;
  features.IsHTTPS = urlObj.protocol === 'https:' ? 1 : 0;

  const tlds = hostname.split('.');
  features.TLDLength = tlds.length > 1 ? tlds[tlds.length - 1].length : 0;
  features.NoOfSubDomain = tlds.length > 2 ? tlds.length - 2 : 0;

  // Character Counts
  features.NoOfLettersInURL = (cleanUrl.match(/[a-zA-Z]/g) || []).length;
  features.LetterRatioInURL = features.NoOfLettersInURL / features.URLLength;
  features.NoOfDegitsInURL = (cleanUrl.match(/\d/g) || []).length;
  features.DegitRatioInURL = features.NoOfDegitsInURL / features.URLLength;
  features.NoOfEqualsInURL = (cleanUrl.match(/=/g) || []).length;
  features.NoOfQMarkInURL = (cleanUrl.match(/\?/g) || []).length;
  features.NoOfAmpersandInURL = (cleanUrl.match(/&/g) || []).length;

  const specialChars = (cleanUrl.match(/[^a-zA-Z0-9]/g) || []).length;
  features.NoOfOtherSpecialCharsInURL = specialChars - (features.NoOfEqualsInURL + features.NoOfQMarkInURL + features.NoOfAmpersandInURL);
  features.SpacialCharRatioInURL = specialChars / features.URLLength;

  // Defaults for complex heuristcs
  features.URLSimilarityIndex = 100.0;
  features.CharContinuationRate = 1.0;
  features.TLDLegitimateProb = 0.5;
  features.URLCharProb = 0.05;
  features.HasObfuscation = 0;
  features.NoOfObfuscatedChar = 0;
  features.ObfuscationRatio = 0;

  // Web Scraping Features
  try {
    const response = await axios.get(cleanUrl, {
      timeout: 5000,
      maxRedirects: 5,
      validateStatus: () => true // Resolve on any status code
    });

    const finalUrl = response.request.res.responseUrl || cleanUrl;
    features.NoOfURLRedirect = finalUrl !== cleanUrl ? 1 : 0;
    features.NoOfSelfRedirect = 0;

    const html = typeof response.data === 'string' ? response.data : '';
    const $ = cheerio.load(html);

    // HTML Structure Features
    const lines = html.split('\n');
    features.LineOfCode = lines.length;
    features.LargestLineLength = Math.max(...lines.map(l => l.length), 0);

    const title = $('title').text() || '';
    features.HasTitle = title.length > 0 ? 1 : 0;
    features.DomainTitleMatchScore = title.toLowerCase().includes(hostname.toLowerCase()) ? 100 : 0;
    features.URLTitleMatchScore = title.toLowerCase().includes(tlds[0].toLowerCase()) ? 100 : 0;

    features.HasFavicon = $('link[rel="icon"], link[rel="shortcut icon"]').length > 0 ? 1 : 0;
    features.Robots = $('meta[name="robots"]').length > 0 ? 1 : 0;
    features.IsResponsive = $('meta[name="viewport"]').length > 0 ? 1 : 0;
    features.HasDescription = $('meta[name="description"]').length > 0 ? 1 : 0;

    features.NoOfPopup = html.toLowerCase().includes('window.open') ? 1 : 0;
    features.NoOfiFrame = $('iframe').length;
    features.HasExternalFormSubmit = $('form[action^="http"]').filter((_, el) => !$(el).attr('action')?.includes(hostname)).length > 0 ? 1 : 0;

    const socialLinks = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com'];
    features.HasSocialNet = $('a').toArray().some(a => socialLinks.some(sl => $(a).attr('href')?.includes(sl))) ? 1 : 0;

    features.HasSubmitButton = $('button[type="submit"], input[type="submit"]').length > 0 ? 1 : 0;
    features.HasHiddenFields = $('input[type="hidden"]').length > 0 ? 1 : 0;
    features.HasPasswordField = $('input[type="password"]').length > 0 ? 1 : 0;

    const text = $('body').text().toLowerCase();
    features.Bank = text.includes('bank') ? 1 : 0;
    features.Pay = text.includes('pay') ? 1 : 0;
    features.Crypto = text.includes('crypto') || text.includes('bitcoin') || text.includes('wallet') ? 1 : 0;
    features.HasCopyrightInfo = text.includes('copyright') || text.includes('©') ? 1 : 0;

    // Resource Counts
    features.NoOfImage = $('img').length;
    features.NoOfCSS = $('link[rel="stylesheet"]').length;
    features.NoOfJS = $('script').length;

    const links = $('a');
    let selfRef = 0, emptyRef = 0, extRef = 0;
    links.each((_, el) => {
      const href = $(el).attr('href') || '';
      if (href === '#' || href === 'javascript:void(0)') emptyRef++;
      else if (href.startsWith('/') || href.includes(hostname)) selfRef++;
      else if (href.startsWith('http')) extRef++;
    });
    features.NoOfSelfRef = selfRef;
    features.NoOfEmptyRef = emptyRef;
    features.NoOfExternalRef = extRef;

  } catch (error) {
    console.error(`Failed to scrape ${cleanUrl}:`, error);
    // If we fail to scrape (e.g., site is down or blocks us), we default the web features to 0
    const webFeatures = [
      'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore',
      'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription',
      'NoOfPopup', 'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
      'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo',
      'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
    ];
    webFeatures.forEach(f => features[f] = 0);
  }

  return features;
};
