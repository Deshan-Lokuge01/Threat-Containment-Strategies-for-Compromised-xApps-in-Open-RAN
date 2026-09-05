function fig_exp3_fourlock()
%FIG_EXP3_FOURLOCK  Per-stage containment latency vs concurrency K.
% Reads exp3_trials.csv (per-trial). Plots raw trial points + median line for
% each stage: identity, NetworkPolicy-selection, service isolation, node
% packet-filter, and final verified-unreachable (T_all_isolated). Self-contained.
% Small n (6/K): raw points are shown, NOT p95/p99.

% ---- STYLE ----
stages={'T_identity_all_s','Identity',[0.031 0.318 0.612]; ...
        'T_policy_all_s','NetworkPolicy-select',[0.192 0.510 0.741]; ...
        'T_service_all_s','Service isolation',[0.42 0.68 0.84]; ...
        'T_nodefilter_all_s','Node packet-filter',[0.902 0.333 0.051]; ...
        'T_all_isolated_s','Verified unreachable',[0.192 0.639 0.329]};
lw=1.8; fsize=11; figsize=[0 0 6.6 4.2];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp3_trials.csv'));
Ks=[1 2 3 4];
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
for s=1:size(stages,1)
    col=stages{s,3}; meds=nan(1,numel(Ks));
    for i=1:numel(Ks)
        v=T.(stages{s,1})(T.K==Ks(i)); v=v(~isnan(v));
        meds(i)=median(v);
        xs=Ks(i)+((1:numel(v))-numel(v)/2)*0.045;
        scatter(ax,xs,v,16,col,'filled','MarkerFaceAlpha',0.45,'HandleVisibility','off');
    end
    plot(ax,Ks,meds,'-o','Color',col,'LineWidth',lw,'MarkerFaceColor',col,'MarkerSize',5,'DisplayName',stages{s,2});
end
xlabel(ax,'Concurrent compromised xApps K','FontSize',fsize);
ylabel(ax,'Attack-onset latency (s)','FontSize',fsize);
xticks(ax,Ks); grid(ax,'on'); ax.GridAlpha=0.3; box(ax,'on'); ax.FontSize=fsize-1;
legend(ax,'Location','northwest','Box','off','FontSize',fsize-2);
title(ax,'Per-stage containment latency vs concurrency (raw points + median)','FontSize',fsize-1);
hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp3_fourlock_vs_K.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp3_fourlock_vs_K.png'),'Resolution',200); close(fig);
end
