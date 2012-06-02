// This file is part of Mongoose project, http://code.google.com/p/mongoose

var chat = {
  // Backend URL, string.
  // 'http://backend.address.com' or '' if backend is the same as frontend
  backendUrl: '',
  maxVisibleMessages: 10,
  errorMessageFadeOutTimeoutMs: 2000,
  errorMessageFadeOutTimer: null,
  lastMessageId: 0,  // tracks the last message we received/sent; hence 1 below the NEXT messageId to use for a chat message but never mind that as the chat SERVER will assign IDs
  getMessagesIntervalMs: 1000,
  getMessagesTimer: null
};

chat.normalizeText = function(text) {
  return text.replace('<', '&lt;').replace('>', '&gt;');
};

chat.refresh = function(data) {
  if (data) {
    $.each(data, function(index, entry) {
      var row = $('<div>').addClass('message-row').appendTo('#mml');
      var timestamp = (new Date(entry.timestamp * 1000)).toLocaleTimeString();
      $('<span>')
        .addClass('message-timestamp')
        .html('[' + timestamp + ']')
        .prependTo(row);
      $('<span>')
        .addClass('message-user')
        .addClass(entry.user ? '' : 'message-user-server')
        .html(chat.normalizeText((entry.user || '[server]') + ':'))
        .appendTo(row);
      $('<span>')
        .addClass('message-text')
        .addClass(entry.user ? '' : 'message-text-server')
        .html(chat.normalizeText(entry.text))
        .appendTo(row);
      if (entry.force_id && 0) {
        chat.lastMessageId = entry.force_id;
        // and go fetch the last remains, pronto...
      } else {
        chat.lastMessageId = Math.max(chat.lastMessageId, entry.id);
      }
    });
    // thanks to closures + timer, you'll get 'very odd' behaviour under load when
    // you're not making absolutely sure that the next refresh request will
    // ALWAYS have the latest intel on our beloved lastMessageId.
    // Hence we must kill & requeue the refresh request given the very probably 
    // updated lastMessageId we're now aware of:
    chat.queueRefresh();
  }

  // Keep only chat.maxVisibleMessages, delete older ones.
  while ($('#mml').children().length > chat.maxVisibleMessages) {
    $('#mml div:first-child').remove();
  }
};

chat.getMessages = function() {
  $.ajax({
    dataType: 'jsonp',
    url: chat.backendUrl + '/ajax/get_messages',
    data: {last_id: chat.lastMessageId},
    success: chat.refresh,
    error: function(o, t, e) {
      var msg = "JSONP error: " + t + " for /ajax/get_messages: " + (e.message || '???') + " (" + o.status + ", " + o.statusText + ") ";
      if (console && typeof(console.log) === 'function')
        console.log(msg, o, e);
      var row = $('<div>').addClass('message-row').appendTo('#mml');
      var timestamp = (new Date()).toLocaleTimeString();
      $('<span>')
        .addClass('message-timestamp')
        .html('[' + timestamp + ']')
        .prependTo(row);
      $('<span>')
        .addClass('message-user')
        .html(chat.normalizeText('[interchange]') + ':')
        .appendTo(row);
      $('<span>')
        .addClass('message-text')
        .addClass('message-error')
        .html(chat.normalizeText(msg))
        .appendTo(row);

      // Keep only chat.maxVisibleMessages, delete older ones.
      while ($('#mml').children().length > chat.maxVisibleMessages) {
        $('#mml div:first-child').remove();
      }

      // wait a few seconds before trying again:
      chat.queueRefresh(5000);
    },
  });
  // given the code in chat.refresh(), chances are that this one
  // will be killed; if we didn't you'll get in trouble with
  // out-of-sync lastMessageId's under load.
  // However, this one has it's use as it'll keep the pipe going
  // while things are quiet in Chatville.
  chat.queueRefresh();
};

chat.queueRefresh = function(timeout) {
  // kill any pending refresh timer and set a new one:
  if (chat.getMessagesTimer)
    window.clearTimeout(chat.getMessagesTimer);
  chat.getMessagesTimer = window.setTimeout(chat.getMessages, timeout || chat.getMessagesIntervalMs);
};

chat.handleMenuItemClick = function(ev) {
  $('.menu-item').removeClass('menu-item-selected');  // Deselect menu buttons
  $(this).addClass('menu-item-selected');  // Select clicked button
  $('.main').addClass('hidden');  // Hide all main windows
  $('#' + $(this).attr('name')).removeClass('hidden');  // Show main window
};

chat.showError = function(message) {
  $('#error').html(message).fadeIn('fast');
  window.clearTimeout(chat.errorMessageFadeOutTimer);
  chat.errorMessageFadeOutTimer = window.setTimeout(function() {
      $('#error').fadeOut('slow');
  }, chat.errorMessageFadeOutTimeoutMs);
};

chat.handleMessageInput = function(ev) {
  var input = ev.target;
  if (ev.keyCode != 13 || !input.value)
    return;
  //input.disabled = true;
  $.ajax({
    dataType: 'jsonp',
    url: chat.backendUrl + '/ajax/send_message',
    data: {text: input.value},
    success: function(ev) {
      input.value = '';
      input.disabled = false;
      chat.getMessages();
    },
    error: function(ev) {
      chat.showError('Error sending message');
      input.disabled = false;
    },
  });
};

$(document).ready(function() {
  $('.menu-item').click(chat.handleMenuItemClick);
  $('.message-input').keypress(chat.handleMessageInput);
  chat.getMessages();
});

// vim:ts=2:sw=2:et
