//$Id$
//ignorei18n_start
var Vault = {
    secretKey: "",
    orgSharedKey: null,
    bookmarkKey: null,
    isAdmin: false,
    isLoggedIn: function(){
        return ZV.validation.isValidString(Vault.secretKey);
    },
    ajax: function (ajaxurl, type, pars, contentType) {
        return new Promise(function(resolve, reject){
            if(type == "POST"){
                if(typeof pars == "string"){
                    pars +="&zvrcsr="+getCSRFCookie();
                }else if(typeof pars == "object"){
                    if(pars == null){pars = {};}
                    if(typeof pars.length == "number"){
                        pars.push({name:'zvrcsr',value:getCSRFCookie()});
                    }else{
                        pars.zvrcsr = getCSRFCookie();
                    }
                }
            }
            $.ajax({
                url: ajaxurl,
                type: type,
                data: pars,
                success: function(data){
                    resolve(data);
                },
                beforeSend: function(xhr) {
                    if(contentType != null){
                        xhr.setRequestHeader( "Content-type", contentType);
                    }
                },
                headers: (($.inArray(type, ['PUT', 'DELETE']) >= 0)? {"X-ZCSRF-TOKEN": "zvrcsr" + "=" + getCSRFCookie()} : {}),//No I18N
                cache: false
            })
                .fail(function(jqXHR, textStatus, errorThrown){
                    if(jqXHR.status == 500){
                        resolve(jqXHR.responseText);
                    }else{
                        if(jqXHR.status == 501){
                            vAlert(i18nString("js.main.enhancements_available"),function(){
                                window.location.reload();
                            });
                        }else if (jqXHR.status == 502){
                            window.location.reload();
                        }
                        else{
                            alert(i18nString('js.error.unable_to_process'));//No I18N
                        }
                    }
                })
                .always(function(){
                    //$('div#ajax_load_tab').hide();
                });
        });
    },
    encrypt: function(plaintext, password){
        if((typeof password == "undefined")||(password == "")){
            return Zohovault.AES.encrypt(plaintext,Vault.secretKey,256);
        }else{
            return Zohovault.AES.encrypt(plaintext,password,256);
        }
    },
    decrypt: function(ciphertext, password){
        if((typeof password == "undefined")||(password == "")){
            return Zohovault.AES.decrypt(ciphertext,Vault.secretKey,256);
        }else{
            if(password == null){
                this.getUserOrgKey();
                return Zohovault.AES.decrypt(ciphertext,Vault.orgSharedKey,256);
            }else{
                return Zohovault.AES.decrypt(ciphertext,password,256);
            }
        }
    },
    fileEncrypt: function(plaintext, password){
        if((typeof password == "undefined")||(password == "")){
            return CryptoJS.AES.encrypt(plaintext,Vault.secretKey).toString();
        }else{
            return CryptoJS.AES.encrypt(plaintext,password).toString();
        }
    },
    fileDecrypt: function(ciphertext, password){
        if((typeof password == "undefined")||(password == "")){
            return CryptoJS.AES.decrypt(ciphertext,Vault.secretKey).toString(CryptoJS.enc.Latin1);
        }else{
            if(password == null){
                this.getUserOrgKey();
                return CryptoJS.AES.decrypt(ciphertext,Vault.orgSharedKey).toString(CryptoJS.enc.Latin1);
            }else{
                return CryptoJS.AES.decrypt(ciphertext,password).toString(CryptoJS.enc.Latin1);
            }
        }
    },
    hash: function(plaintext){
        return Zohovault.hash(plaintext);
    },
    Base64_encode: function(input){
        return Zohovault.Base64.encode(input);
    },
    Base64_decode: function(input){
        return Zohovault.Base64.decode(input);
    },
    RSA_encrypt: function(plaintext, publicKey){

        var rsa = new RSAKey();
        rsa.setPublic(publicKey, '10001');
        var res = rsa.encrypt(plaintext);
        if(res) {
            ciphertext = res;
            return ciphertext;
        }
    },
    RSA_decrypt: function(ciphertext, privateKey){
        privateKey = privateKey.split(',');
        var rsa = new RSAKey();
        rsa.setPrivateEx(privateKey[0], privateKey[1], privateKey[2], privateKey[3], privateKey[4], privateKey[5], privateKey[6], privateKey[7]);
        if(ciphertext.length == 0) {
            return;
        }
        var plaintext = rsa.decrypt(ciphertext);
        return plaintext;
    },
    PBKDF2_key: function(password, salt, iteration){
        /** SJCL and Crypto-js output compatibility changes
         *  SJCL <SALT> converting toHex() value.
         */
        function toHex(str) {
            var hex = '';
            for(var i=0;i<str.length;i++) {
                hex += ''+str.charCodeAt(i).toString(16);
            }
            return hex;
        }
        var hmacSHA256 = function (key) {
            var hasher = new sjcl.misc.hmac( key, sjcl.hash.sha256 );
            this.encrypt = function () {
                return hasher.encrypt.apply( hasher, arguments );
            };
        };
        var passwordSalt = sjcl.codec.hex.toBits(toHex(salt));
        var derivedKey = sjcl.misc.pbkdf2( password, passwordSalt, iteration, 256, hmacSHA256 );
        return sjcl.codec.hex.fromBits( derivedKey );
    },
    authJSONStr: function(){
        var authJSON = {};
        authJSON.date = new Date();
        return JSON.stringify(authJSON);
    },
    getUserOrgKey: function(){
        $.ajax({
            url: "/orgusers/orgkey.do",
            type: "POST",
            data: {action:"getSharedpass",zvrcsr:getCSRFCookie()},
            async: false,
            success: function(ORG){
                if((typeof ORG.P != "undefined") && (typeof ORG.K != "undefined")){
                    Vault.orgSharedKey = Vault.RSA_decrypt(ORG.K,Vault.decrypt(ORG.P));
                }
            }
        });
    }
};

var VaultSharing = {
    adminUser:true,
    privateKey: new Array(),
    enable: function(){
        this.genRSA();
        var publicKey = this.privateKey[0];
        var privateKey = this.privateKey.toString();
        var oneTimePassphrase = (this.adminUser) ? Vault.RSA_encrypt(generateOrgKey(), publicKey) : null;
        var data = {
            action: (typeof action !='undefined')? action : "setUserCertificate",
            publicKey: publicKey,
            privateKey: Vault.encrypt(privateKey),
            onetimepassphrase: oneTimePassphrase
        };
        return data;
        //Vault.ajax('/vaultkey.do',"POST",data,callbackFun);
    },
    genRSA: function(){

        var rsa = new RSAKey();
        var dr = document.rsatest;
        rsa.generate(parseInt(1024),'10001');

        this.privateKey[0] = rsa.n.toString(16);
        this.privateKey[1] = '10001';
        this.privateKey[2] = rsa.d.toString(16);
        this.privateKey[3] = rsa.p.toString(16);
        this.privateKey[4] = rsa.q.toString(16);
        this.privateKey[5] = rsa.dmp1.toString(16);
        this.privateKey[6] = rsa.dmq1.toString(16);
        this.privateKey[7] = rsa.coeff.toString(16);
    }
};

//Used for ORG key generation
var ZV ={}
ZV.PWD_generater = {

    getRandomNum: function(lbound, ubound) {
        return (Math.floor(Math.random() * (ubound - lbound)) + lbound);
    },
    getRandomChar: function(number, lower, upper, other, extra) {
        var numberChars = "0123456789";
        var lowerChars = "abcdefghijklmnopqrstuvwxyz";
        var upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var otherChars = "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";
        var charSet = extra;
        if (number == true){
            charSet += numberChars;}
        if (lower == true){
            charSet += lowerChars;}
        if (upper == true){
            charSet += upperChars;}
        if (other == true){
            charSet += otherChars;}
        return charSet.charAt(this.getRandomNum(0, charSet.length));
    },
    getPassword: function(length, extraChars, firstNumber, firstLower, firstUpper, firstOther, latterNumber, latterLower, latterUpper, latterOther) {
        var rc = "";
        if (length > 0){
            rc = rc + this.getRandomChar(firstNumber, firstLower, firstUpper, firstOther, extraChars);
        }
        for (var idx = 1; idx < length; ++idx) {
            rc = rc + this.getRandomChar(latterNumber, latterLower, latterUpper, latterOther, extraChars);
        }
        return rc;
    }
};
function generateOrgKey(){
    return ZV.PWD_generater.getPassword(32,'',true, true,true, true, true, true, true,true);
}

function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for(var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}
function eraseCookie(name) {
    setCookie(name,"",-1);
}

function getCSRFCookie() {
    var csrf = getCookie("zvcsr");
    return csrf;
};
//ignorei18n_end
if(ZV == undefined){
    var ZV = {};//constants
}

ZV.validation = {
    isValidURL: function(url){
        var RegExp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;
        if(RegExp.test(url)){return true;}else{return false;}
    },
    isValidEmail: function(email){
        var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(email);
    },
    getFailedCharString: function(testString,regex){
        var arr = (testString).split(regex).join('');
        var invalidChar=[];
        for (var i = 0; i < arr.length; i++)
        {
            if (($.inArray(arr[i], invalidChar)) == -1 && arr[i]!== '' && arr[i]!== undefined)
            {
                invalidChar.push(arr[i]);
            }
        }
        return invalidChar.join(', ');
    },
    isValidFileName: function(fileName){
        var re = /[0-9a-zA-Z()_\-\.\$@\?\,\:\'\/\!\s]+/;
        var failedChar = ZV.validation.getFailedCharString(fileName,re);
        if(failedChar !== ''){
            vAlert(I18N.getMsg("js.error.invalid_filename",new Array([failedChar])));
            return false;
        }
        return true;
    },
    validateString: function(regex, str){
        var arrMatch = [];
        while(res = regex.exec(str)){
            var resStr = ''+res;
            if (($.inArray(resStr, arrMatch)) === -1)
            {
                arrMatch.push(resStr);
            }
        }
        // For IE browser '<' char not showing, so fix added
        for(var i=0; i< arrMatch.length; i++){
            var resStr = ''+arrMatch[i];
            if(resStr === '<'){
                arrMatch[i] = '&lt;';
            }else if(resStr === '&'){
                arrMatch[i] = '&amp;';
            }
        }
        return arrMatch.join(',');
    },
    getCharNotMatchingRegex:function(regex,str){
        var arrMatch = [];
        var len = str.length;
        for(var i=0; i< len; i++){
            if(!regex.test(str[i])){
                if(arrMatch.indexOf(str[i]) == -1){
                    arrMatch.push(str[i]);
                }
            }
        }
        // For IE browser '<' char not showing, so fix added
        if(getBrowserName() == "ie"){
            for(var i=0; i< arrMatch.length; i++){
                var resStr = ''+arrMatch[i];
                if(resStr === '<'){
                    arrMatch[i] = '&lt;';
                }else if(resStr === '&'){
                    arrMatch[i] = '&amp;';
                }
            }
        }
        return arrMatch.join(',');
    },
    isValidOrgName: function(orgName){
        failedChar = ZV.validation.validateString(ZV.pattern.XSS, orgName);
        if(failedChar !== ""){
            vAlert(I18N.getMsg("js.error.invalid_orgname",new Array([failedChar])));
            return false;
        }
        return true;
    },
    isValidPassword : function(el, pol){
        //var fullRegEx = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
        var errorEl = $(el).parents('.zvcenter-label');
        //errorEl.hide();
        var password = $(el).val();
        var minLength = pol.MINLENGTH;
        var maxLength = pol.MAXLENGTH;
        var regEx;
        var regExCap = /[A-Z]/;
        errorEl.find('.errormsg-text').html('');
        //check if starts with alphabet
        if (pol.BEGINWITHLETTER == 1 ){
            var first = password.charAt(0);
            first = first.toUpperCase();
            if(!regExCap.test(first)){
                errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.being_with_letter'))
                //.addClass("error1")
                //.prepend('<span class="arrow"></span>');
                // errorEl.show();
                return false;
            }
        }
        //check for min length
        if(password.length < minLength){
            errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.minlength', [minLength]))
            //.addClass("error1")
            //.prepend('<span class="arrow"></span>');
            //errorEl.show();
            return false;
        }
        //check for max length
        if(password.length > maxLength){
            errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.maxlength', [maxLength]))
            // .addClass("error1")
            // .prepend('<span class="arrow"></span>');
            // errorEl.show();
            return false;
        }
        //check for mixed case password
        regEx = /[a-z]/;
        var reqmixedcase = pol.REQMIXEDCASE;
        if(reqmixedcase == 1){
            if(!regEx.test(password)){
                errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.atleastone_lowercase'))
                // .addClass("error1")
                // .prepend('<span class="arrow"></span>');
                //errorEl.show();
                return false;
            }else if (!regExCap.test(password)){
                errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.atleastone_uppercase'))
                //.addClass("error1")
                //.prepend('<span class="arrow"></span>');
                // errorEl.show();
                return false;
            }
        }
        //check for at least one number
        regEx = /[0-9]/;
        var reqnumerals = pol.REQNUMERALS;
        if(reqnumerals == 1 && !regEx.test(password)){
            errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.atleaseone_number'))
            //.addClass("error1")
            //.prepend('<span class="arrow"></span>');
            //errorEl.show();
            return false;
        }
        //check for special characters
        //regEx = /.[!,@,#,$,%,^,&,*,?,_,~,\-,(,),=]/;
        regEx = /.[!,@,#,$,%,^,&,*,?,_,~,\-,(,),=,+,.,:,{,;,},<,>,|,[,\]]/;
        var reqspclchar = pol.REQSPCLCHAR;
        var numofspclchar = pol.NUMOFSPCLCHAR;
        if(reqspclchar == 1 && !regEx.test(password)){
            errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.atleast_specialchars', [numofspclchar]))
            // .addClass("error1")
            // .prepend('<span class="arrow"></span>');
            // errorEl.show();
            return false;
        }
        if(reqspclchar == 1 && numofspclchar > 0){
            //regEx = /[!,@,#,$,%,^,&,*,?,_,~,\-,(,),=]/g;
            regEx = /[!,@,#,$,%,^,&,*,?,_,~,\-,(,),=,+,.,:,{,;,},<,>,|,[,\]]/g;
            var count = 0;
            var arr = password.match(regEx);
            if(arr != null){
                count = arr.length;
            }
            if(count < numofspclchar){
                errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.atleast_specialchars', [numofspclchar]))
                //  .addClass("error1")
                // .prepend('<span class="arrow"></span>');
                // errorEl.show();
                return false;
            }

        }
        //check for not required characters
        var isnotreqchars = pol.NOTREQCHARS;
        if(typeof isnotreqchars != 'undefined' && isnotreqchars.length > 0){
            for(var index=0; index<isnotreqchars.length;index++){
                if(password.indexOf(isnotreqchars[index]) !== -1){
                    errorEl.addClass('errormsg').find('.errormsg-text').html(I18N.getMsg('js.error.password.characters_not_allowed', [isnotreqchars[index]]))
                    //   .addClass("error1")
                    //   .prepend('<span class="arrow"></span>');
                    // errorEl.show();
                    return false;

                }
            }
        }
        // $("#"+el.name+"_error").hide().removeClass('error1');
        return true;
    },
    compareTime : function(fromHrs, fromMins, toHrs, toMins){
        if(fromHrs == toHrs && fromMins == toMins){
            return false;
        }
        if(fromHrs > toHrs){
            return false;
        }else if (fromHrs == toHrs && fromMins > toMins){
            return false;
        }else{
            return true;
        }
    },
    isValidString: function(data) {
        return typeof data !== "undefined" && data !== null && data !== "";
    },
    isSharingEnabled: function(){
        return ZV.validation.isValidString(Vault.orgSharedKey);
    }
};

ZV.pattern = {
    URL:/^(http(s?)|((s|t)?)ftp|ssh|file|telnet|nfs)\:\/\/[-.\w]*(\/?)([a-zA-Z0-9\-\.\?\,\:\;\'\/\\\+=&%\$#_@*|~]*)?$/,
    secretName:/^[0-9a-zA-Z_\-\.\$@\?\,\:\'\/\!}\s]+$/,
    XSS:/[<>"&\/()\[\]]/g
};

var I18N = {};
I18N.getMsg= function(key,valary)
{
    if(typeof i18nJSON=="undefined" || i18nJSON==null)
    {
        return key;
    }
    key = $.trim(key);
    var value = (i18nJSON[key]!=null)?i18nJSON[key]:key;
    if(valary)
    {
        for(var i=0; i < valary.length; i++)
        {
            var regExp = new RegExp("\\\{" + i + "\\\}");
            value = value.replace(regExp, valary[i]);
        }
    }
    if(value.includes("Zoho Vault")){
        if(key!="js.text.import.zohovault" && key!="js.text.invalid_import_data_3" && key!="js.error.invalid_import_data_2"){
            if(ZV.rebrandingDetails!=undefined && ZV.rebrandingDetails!=null && ZV.rebrandingDetails.status && ZV.rebrandingDetails.companyName!=undefined && ZV.rebrandingDetails.companyName!=null){
                while(value.includes("Zoho Vault")){//No I18N
                    value=value.replace("Zoho Vault",htmlEncode(ZV.rebrandingDetails.companyName));//No I18N
                }
            }
        }
    }
    return value;
}

function htmlEncode(value){
    if (value) {
        return jQuery('<div/>').text(value).html(); 	//No I18N
    } else {
        return '';
    }
}
function escapeQuotes(str) {
    var tagsToReplace = {
        '"': '&quot;',
        '\'': '&#39;'
    };
    return str.replace(/[&<>"']/g, function(tag) {
        return tagsToReplace[tag] || tag;
    });
}

function postAjax (url,data){
    return new Promise(function(resolve, reject){
        if(typeof data == "string"){
            data +="&zvrcsr="+getCSRFCookie();//No I18N
        }else if(typeof data == "object"){//No I18N
            if(data == null){data = {};}
            if(typeof data.length == "number"){
                data.push({name:'zvrcsr',value:getCSRFCookie()});
            }else{
                data.zvrcsr = getCSRFCookie();
            }
        }
        $.ajax({
            url: url,
            type: "POST",//No I18N
            data: data,
            success: function(data){
                resolve(data);
            },
            cache: false
        }).fail(function(jqXHR, textStatus, errorThrown){
            if(jqXHR.status == 500){
                resolve(jqXHR.responseText);
            }else{
                if(jqXHR.status == 501){
                    //vAlert("js.main.enhancements_available"),function(){
                    window.location.reload();
                    //});
                }else if (jqXHR.status == 502){
                    window.location.reload();
                }
                else{
                    alert(i18nString('js.error.unable_to_process'));//No I18N
                }
            }
        }).always(function(){
            //$('div#ajax_load_tab').hide();
        });
    });

}

function getAjax (url, data){
    return new Promise(function(resolve, reject){
        $.ajax({
            url: url,
            type: "GET",//No I18N
            data: data,
            success: function(data){
                resolve(data);
            },
            cache: false
        }).fail(function(jqXHR, textStatus, errorThrown){
            if(jqXHR.status == 500){
                resolve(jqXHR.responseText);
            }else{
                if(jqXHR.status == 501){
                    //vAlert("js.main.enhancements_available"),function(){
                    window.location.reload();
                    //});
                }else if (jqXHR.status == 502){
                    window.location.reload();
                }
                else{
                    alert(i18nString('js.error.unable_to_process'));//No I18N
                }
            }
        }).always(function(){
            //$('div#ajax_load_tab').hide();
        });
    });
}
function setTitle (element,text) {
    if(element.offsetWidth < element.scrollWidth){
        if(text == undefined){
            element.setAttribute("lt-prop-title",element.innerText);
        } else {
            element.setAttribute("lt-prop-title",text);
        }
    }
    else{
        element.removeAttribute("lt-prop-title");
    }
}

function replaceOldStrings (oldString){
    if(oldString != undefined){
        var newString = oldString.replace("Secret","Password");
        newString = newString.replace("Password Type","Password Category");
        newString = newString.replace("Chamber","Folder");
        if((newString != "Viewed secret access report") && (newString != "Exported secret access report")){
            newString = newString.replace("secret","password");
        }
        newString = newString.replace("chamber","folder");
        newString = newString.replace("Password Assessment Report Initiated","Dashboard Accessed");
        newString = newString.replace("miscellaneous","others");
        newString = newString.replace("user audit","user and groups audit");
        newString = newString.replace("outsider sharing report","third party sharing report");
        newString = newString.replace("password access report","active users and passwords report");
        newString = newString.replace("password security analysis report","password assessment report");
        newString = newString.replace("secret access report","password access report");
        newString = newString.replace("passphrase","master password");
        newString = newString.replace("Passphrase","Master password");
        newString = newString.replace("outsiders","third parties");
        newString = newString.replace("Outsiders","Third parties");
        newString = newString.replace("Outsider","Third party");
        newString = newString.replace("outsider","third party");
        newString = newString.replace("TFA", "MFA");
        return newString;
    }
    return oldString;
}
//ignorei18n_end

Number.prototype.pad = function(size) {
    var string = String(this);
    while (string.length < size) {
        string = "0" + string;
    }
    return string;
}
var trialBannerHeight = 36;
var topHeaderHeight = 50;
function resizeVaultUI(){
    var height = getWindowHeight();
    if($('body').hasClass('top-banner')){
        height = height - trialBannerHeight;
    }
    height = height - topHeaderHeight;
    var routeName = "";
    if (Lyte.Router.getRouteInstance() != undefined) {
        routeName =  Lyte.Router.getRouteInstance().routeName;
    }

    if(routeName == "list"){
        $('.password-list-panel').css({'height': height - 87});
        if(ZV.License.USER_PLAN == ZV.License.PLAN_FREE){
            $('#folder-tree-view').css('height', height - 168);
        }else{
            $('#folder-tree-view').css('height', height - 250);
        }
    } else if(routeName == "show-apps"){ //No I18N
        $('#apps-left').css({'height': height});
        $('#my-apps-cont').css({'height': height - 45});
    } else if(routeName == "manage"){ //No I18N
        $('#apps-left').css({'height': height });
        if(document.querySelector("manage-apps") != null){
            var manageAppsData = document.querySelector("manage-apps").component.getData()
            if(manageAppsData.appContentArray.length > 0){
                $('#allAppsData').css({'height': height - 95});
            } else {
                $('#allAppsData').css({'height': 0});
            }
            var userAccess = document.querySelector("user-access")
            if(userAccess != null){
                userAccess = userAccess.component.getData()
                /*if($('body').hasClass('top-banner')){
                    height = height + 36;
                }*/
                if(userAccess.needBreadCrumbs) {
                    $('#users-selected').css({'height': height - 229});
                } else {
                    $('#users-selected').css({'height': height - 385});
                }
                if(userAccess.showStep){
                    $('#manage-app-access-cont').css({'height': height - 240});
                } else {
                    $('#manage-app-access-cont').css({'height': height - 205});
                }
                $('#user-list').css({'height': height - 220});
                $('#add-new-app-cont').css({'height': height - 245});
                $('#application-details').css({'height': height - 290});
                if(userAccess.isSuppApp){
                    $('#add-new-app-cont').css({'height': height - 225});
                }
                $('#idp-details-cont').css({'height': height - 195});
                $('#supp-app-container').css({'height': height - 131});
            }
        }
    } else if(routeName == "folders"){//No I18N
        var foldersContainer = document.querySelector("folders-container")
        if(foldersContainer != null){
            foldersContainer = foldersContainer.component.getData()
            if(foldersContainer.formattedFolderData.length == 0){
                $('#folders-content').css({'height': 0});
            } else {
                $('#folders-content').css({'height': height - 134});
            }
        }
    }else if(routeName == "reports"){ 		//No I18N
        $('div.report-right-panel').css({'height': height});
        $('div.audit-left-panel').css({'height': height});
    }else if(routeName == "audit"){			//No i18N
        $('div.audit-right-panel').css({'height': height});
        $('div.audit-left-panel').css({'height': height});
        var tableHeight = height - 85;
        var filterPanelHeight = $L('.filter-show-panel')[0].style.display == 'none' ? 0 : 62;
        tableHeight = tableHeight - filterPanelHeight;
        var tables = document.getElementsByClassName("auditTable"); 	//No I18N
        for(i=0;i<tables.length;i++)
        {
            tables[i].style.height = tableHeight + 'px';
        }
    }else if(routeName == "dashboard"){		//No I18N
        document.getElementById("dashboard-switch").setAttribute("lt-prop-height", height + 'px');
    }

    var rightPanel = document.getElementById('user-profile-body');
    if(rightPanel != undefined){
        rightPanel.style.height = (height - 187) + 'px';
    }

    var transitionTarget = Lyte.Router.getRouteInstance().transition.target;

    if (transitionTarget.startsWith('main.settings')) {
        $L('#consolidated-settings-scroll-div').css({'height': height - 91});//No I18N
        $L('#consolidated-settings-scroll-div')[0].scroll();//No I18N

        $L('#settings-left-panel-scroll-div').css({'height': height - 55});//No I18N
        $L('#settings-left-panel-scroll-div')[0].scroll();//No I18N

        $L('#settings-right-panel').css({'height': height }); //No I18N
        $L('#settings-right-panel')[0].scroll(); //No I18N
    }

    switch(transitionTarget) {
        case 'main.settings.user-management': //No I18n
            /* Users table height */
            var filterPanelHeight = $L('#filter-panel')[0].style.display == 'none' ? 0 : 62;
            if ($L('#users-table lyte-td').length > 0) {
                $L('#users-table').height($L('#settings-right-panel').height() - 135 - filterPanelHeight); //No I18n
            } else {
                $L('#users-table').height('auto'); //No I18n
            }

            /* Set height for slider */
            $L('#add-user-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#add-user-slider div.modal-panel-body').height((height - 140) + 'px'); //No I18n

            /* Set height for user-selector in slider */
            $L('#add-user-slider div.modal-panel-body #add-user-list').height((height - 305) + 'px'); //No I18n
            $L('#add-user-slider div.modal-panel-body #add-user-list').scroll(); //No I18n
            break;
        case 'main.settings.user-group': //No I18n
            /* User group table height */
            var filterPanelHeight = $L('#filter-panel')[0].style.display == 'none' ? 0 : 62;
            if ($L('#groups-table lyte-td').length > 0) {
                $L('#groups-table').height($L('#settings-right-panel').height() - 85 - filterPanelHeight	); //No I18n
            } else {
                $L('#groups-table').height('auto'); //No I18n
            }

            /* Set height for slider */
            $L('#user-group-user-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#user-group-user-slider div.modal-panel-body').height((height - 141) + 'px'); //No I18n

            /* Set height for user-selector in slider */
            $L('#user-group-user-slider div.modal-panel-body #add-user-list').height((height - 470) + 'px'); //No I18n
            $L('#user-group-user-slider div.modal-panel-body #add-user-list').scroll(); //No I18n
            $L('#group-details-slider div.modal-panel-body').height((height - 161) + 'px'); //No I18n
            break;
        case 'main.settings.password-policies': //No I18n
            $L('#policies-table').height($L('#settings-right-panel').height() - 85); //No I18n
            break;
        case 'main.settings.secret-types': //No I18n
            /* Secret types table height */
            if ($L('#types-table lyte-td').length > 0) {
                $L('#types-table').height($L('#settings-right-panel').height() - 80); //No I18n
            } else {
                $L('#types-table').height('auto'); //No I18n
            }
            break;
        case 'main.settings.password-access-requests': //No I18n
            /* Access requests table height */
            if ($L('#access-requests-table lyte-td').length > 0) {
                $L('#access-requests-table').height($L('#settings-right-panel').height() - 135); //No I18n
            } else {
                $L('#access-requests-table').height('auto'); //No I18n
            }
            break;
        case 'main.settings.notifications': //No I18n
            if ($L('#settings-table lyte-td').length > 0) {
                $L('#settings-table').height($L('#settings-right-panel').height() - 85); //No I18n
            } else {
                $L('#settings-table').height('auto'); //No I18n
            }
            break;
        case 'main.settings.emergency-access': //No I18n
            if ($L('#emergency-contacts-table lyte-td').length > 0) {
                $L('#emergency-contacts-table').height($L('#settings-right-panel').height() - 85); //No I18n
            } else {
                $L('#emergency-contacts-table').height('auto'); //No I18n
            }
            break;
        case 'main.settings.ip-restriction': //No I18n
            if ($L('#restrictions-table lyte-td').length > 0) {
                $L('#restrictions-table').height($L('#settings-right-panel').height() - 85); //No I18n
            } else {
                $L('#restrictions-table').height('auto'); //No I18n
            }
            $L('#ip-exemption-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#ip-exemption-slider div.modal-panel-body').height((height - 136) + 'px'); //No I18n
            $L('#ip-restriction-user-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#ip-restriction-user-slider div.modal-panel-body').height((height - 140) + 'px'); //No I18n
            break;
        case 'main.settings.fine-grained-controls': //No I18n
            $L('#manage-exemption-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#manage-exemption-slider div.modal-panel-body').height((height - 136) + 'px'); //No I18n
            $L('#fine-grained-user-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#fine-grained-user-slider div.modal-panel-body').height((height - 140) + 'px'); //No I18n
            break;
        case 'main.settings.data-backup': //No I18n
            $L('#backup-exemption-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#backup-exemption-slider div.modal-panel-body').height((height - 136) + 'px'); //No I18n
            $L('#data-backup-user-slider div.modal-panel-body').css('maxHeight', 'unset'); //No I18n
            $L('#data-backup-user-slider div.modal-panel-body').height((height - 140) + 'px'); //No I18n
            break;
    }
}
$(window).resize(function() {
    resizeVaultUI();
});
function getWindowHeight(){
    return $(window).height();
}
