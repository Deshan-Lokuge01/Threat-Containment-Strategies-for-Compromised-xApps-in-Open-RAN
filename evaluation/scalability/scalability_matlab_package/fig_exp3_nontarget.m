function fig_exp3_nontarget()
%FIG_EXP3_NONTARGET  Non-target correctness by K (stacked outcome bars).
% Reads exp3_trials.csv. Shows, per K, how many valid trials were fully
% successful vs failed on non-target reachability. Self-contained.

% ---- STYLE ----
col_ok=[0.192 0.639 0.329]; col_fail=[0.902 0.333 0.051];
fsize=11; figsize=[0 0 5.4 3.6];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp3_trials.csv'));
Ks=[1 2 3 4]; ok=zeros(1,4); ntfail=zeros(1,4);
for i=1:numel(Ks)
    sub=T(T.K==Ks(i),:);
    ok(i)=sum(sub.trial_success==1);
    ntfail(i)=sum(sub.trial_success==0 & sub.all_nontargets_reachable==0);
end
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
b=bar(ax,Ks,[ok' ntfail'],'stacked');
b(1).FaceColor=col_ok; b(2).FaceColor=col_fail;
legend(ax,{'Success (targets contained, non-targets OK)','Non-target reachability fail (transient)'},...
    'Location','southoutside','Box','off','FontSize',fsize-3);
for i=1:numel(Ks), text(ax,Ks(i),ok(i)+ntfail(i)+0.15,sprintf('%d/%d',ok(i),ok(i)+ntfail(i)),'HorizontalAlignment','center','FontSize',fsize-2); end
xlabel(ax,'Concurrent compromised xApps K','FontSize',fsize); ylabel(ax,'Valid trials (n=6/K)','FontSize',fsize);
xticks(ax,Ks); ylim(ax,[0 6.8]); grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
title(ax,'Non-target correctness by concurrency','FontSize',fsize-1); hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp3_nontarget_correctness.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp3_nontarget_correctness.png'),'Resolution',200); close(fig);
end
